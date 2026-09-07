//! # yamux 多路复用会话
//!
//! 封装 paritytech/yamux（0.13，poll-based API）为 async 友好的会话抽象：
//!
//! - **driver 任务**独占 `yamux::Connection`，轮询三类事件源：
//!   1. 入站流（对端打开的新流）→ mpsc 通道交付 [`MuxSession::accept_stream`]
//!   2. 出站流打开请求 → 命令通道 + oneshot 回执交付 [`MuxSession::open_stream`]
//!   3. 关闭命令（优雅关闭，发送 GoAway）
//! - 单次 poll 内同时推进入站与 pending open（避免 ACK 积压死锁：
//!   `poll_new_outbound` 在 ACK backlog 满时返回 Pending，而 ACK 帧
//!   只能从 `poll_next_inbound` 读到，两者必须同轮询推进）
//!
//! ## trait 桥接
//!
//! yamux 0.13 实现的是 `futures::io` 的 AsyncRead/AsyncWrite，
//! 本项目统一使用 `tokio::io` trait，两个方向都用
//! `tokio_util::compat::Compat` 适配：
//!
//! - 底层 IO（tokio TCP/TLS）→ `TokioAsyncReadCompatExt::compat()` → futures 流
//! - yamux Stream（futures 流）→ `FuturesAsyncReadCompatExt::compat()` → tokio 流
//!
//! ## 生命周期
//!
//! 会话生命周期 = 一次控制连接登录，不跨重连存活；
//! 控制流（首条流）退出后调用 [`MuxSession::close`]，后续流随之终结。
//!
//! ## 适用范围
//!
//! 仅 TCP 控制连接（对齐 frp 原版 tcp_mux 仅 TCP 生效）：
//! KCP 有独立 UDP 语义、WebSocket 已是应用层流，均不复用。

use crate::{AnyConn, FrpConn, NetError};
use futures_util::future::poll_fn;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// 多路复用协商魔数（TCP 层首字节）
///
/// 客户端 tcp_mux 开启时，TCP 连接后先写此字节再进行 TLS 握手；
/// 服务端 peek 首字节判定：命中走多路复用路径，否则走旧协议路径（兼容旧客户端）。
pub const TCP_MUX_MAGIC: u8 = 0x5A;

/// 会话内部命令
enum Cmd {
    /// 打开一条出站流（oneshot 回执）
    Open(oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>),
    /// 优雅关闭（发送 GoAway 并排空）
    Close,
}

/// driver 单次 poll 产生的事件
enum Event {
    /// 对端打开了新流
    Inbound(yamux::Stream),
    /// 一条 pending open 已完成（成功或失败）
    OpenDone,
    /// 新命令
    Cmd(Cmd),
    /// 命令通道全部关闭（所有 MuxSession 已 drop）
    CmdClosed,
    /// 连接关闭（对端断开 / 协议错误 / 优雅关闭完成）
    Closed,
}

/// yamux 多路复用会话
///
/// 通过 `Arc<MuxSession>` 共享；driver 任务持有连接本体，
/// 打开/接受流均经通道完成，天然线程安全。
pub struct MuxSession {
    /// 出站流打开 / 关闭命令通道
    cmd_tx: mpsc::Sender<Cmd>,
    /// 入站流接收器（accept_stream 经 AsyncMutex 共享）
    inbound_rx: AsyncMutex<mpsc::Receiver<yamux::Stream>>,
    /// 会话关闭标志（driver 退出时置位）
    closed: Arc<AtomicBool>,
    /// driver 任务句柄（持有防 drop）
    _driver: JoinHandle<()>,
}

impl MuxSession {
    /// 以服务端模式接管底层连接（tokio IO）
    pub fn new_server<T>(io: T) -> Arc<Self>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(io.compat(), yamux::Mode::Server)
    }

    /// 以客户端模式接管底层连接（tokio IO）
    pub fn new_client<T>(io: T) -> Arc<Self>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(io.compat(), yamux::Mode::Client)
    }

    fn new<T>(io: T, mode: yamux::Mode) -> Arc<Self>
    where
        T: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin + Send + 'static,
    {
        let connection = yamux::Connection::new(io, yamux::Config::default(), mode);
        let (inbound_tx, inbound_rx) = mpsc::channel::<yamux::Stream>(64);
        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(64);
        let closed = Arc::new(AtomicBool::new(false));
        let driver = tokio::spawn(driver_loop(
            connection,
            cmd_rx,
            inbound_tx,
            closed.clone(),
        ));
        Arc::new(Self {
            cmd_tx,
            inbound_rx: AsyncMutex::new(inbound_rx),
            closed,
            _driver: driver,
        })
    }

    /// 打开一条出站流（客户端建立工作连接）
    ///
    /// 返回类型擦除连接，可直接用于消息读写与桥接。
    pub async fn open_stream(&self) -> Result<AnyConn, NetError> {
        if self.is_closed() {
            return Err(NetError::Other("mux session closed".into()));
        }
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Open(tx))
            .await
            .map_err(|_| NetError::Other("mux session closed".into()))?;
        match rx.await {
            Ok(Ok(stream)) => Ok(Box::new(stream.compat())),
            Ok(Err(e)) => Err(NetError::Other(format!("yamux open stream: {}", e))),
            Err(_) => Err(NetError::Other("mux session closed".into())),
        }
    }

    /// 接受一条入站流（服务端分发工作连接）
    ///
    /// 会话关闭后返回错误。
    pub async fn accept_stream(&self) -> Result<AnyConn, NetError> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv()
            .await
            .map(|s| Box::new(s.compat()) as AnyConn)
            .ok_or_else(|| NetError::Other("mux session closed".into()))
    }

    /// 会话是否已关闭
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.cmd_tx.is_closed()
    }

    /// 优雅关闭会话（发送 GoAway，driver 排空后退出）
    pub async fn close(&self) {
        let _ = self.cmd_tx.send(Cmd::Close).await;
    }
}

/// driver 主循环：独占 yamux::Connection，轮询入站流 / pending open / 命令
async fn driver_loop<T>(
    mut connection: yamux::Connection<T>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    inbound_tx: mpsc::Sender<yamux::Stream>,
    closed: Arc<AtomicBool>,
) where
    T: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    // 待完成的出站流打开请求（FIFO）
    let mut pending_opens: VecDeque<
        oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>,
    > = VecDeque::new();

    loop {
        let event = poll_fn(|cx| {
            // 1. 入站流优先：既交付新流，也推进 pending open 所依赖的 ACK 帧
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => return Poll::Ready(Event::Inbound(stream)),
                Poll::Ready(Some(Err(e))) => {
                    log::debug!("yamux driver: inbound error: {}", e);
                    return Poll::Ready(Event::Closed);
                }
                Poll::Ready(None) => return Poll::Ready(Event::Closed),
                Poll::Pending => {}
            }

            // 2. 推进 pending open 队列头部（同一轮只处理一个，回到循环重新平衡）
            if !pending_opens.is_empty() {
                match connection.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        if let Some(reply) = pending_opens.pop_front() {
                            let _ = reply.send(Ok(stream));
                        }
                        return Poll::Ready(Event::OpenDone);
                    }
                    Poll::Ready(Err(e)) => {
                        if let Some(reply) = pending_opens.pop_front() {
                            let _ = reply.send(Err(e));
                        }
                        return Poll::Ready(Event::OpenDone);
                    }
                    Poll::Pending => {}
                }
            }

            // 3. 命令通道
            match cmd_rx.poll_recv(cx) {
                Poll::Ready(Some(cmd)) => return Poll::Ready(Event::Cmd(cmd)),
                Poll::Ready(None) => return Poll::Ready(Event::CmdClosed),
                Poll::Pending => {}
            }

            Poll::Pending
        })
        .await;

        match event {
            Event::Inbound(stream) => {
                if inbound_tx.send(stream).await.is_err() {
                    // 接收端全部 drop（MuxSession 已释放），会话无意义
                    log::debug!("yamux driver: inbound channel closed, stopping");
                    break;
                }
            }
            Event::OpenDone => {}
            Event::Cmd(Cmd::Open(reply)) => pending_opens.push_back(reply),
            Event::Cmd(Cmd::Close) => {
                log::debug!("yamux driver: graceful close requested");
                let _ = poll_fn(|cx| connection.poll_close(cx)).await;
                break;
            }
            Event::CmdClosed | Event::Closed => break,
        }
    }

    closed.store(true, Ordering::SeqCst);
}

/// yamux 流（经 Compat 适配）满足 FrpConn：多路复用流无独立远端地址
impl FrpConn for tokio_util::compat::Compat<yamux::Stream> {
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 内存双工流（tokio IO）
    async fn duplex_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        tokio::io::duplex(4096)
    }

    /// echo 服务：接受一条流并原样回写
    async fn spawn_echo_session(session: Arc<MuxSession>) {
        tokio::spawn(async move {
            while let Ok(mut stream) = session.accept_stream().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
    }

    #[tokio::test]
    async fn test_mux_session_open_accept_echo() {
        let (a, b) = duplex_pair().await;
        let server = MuxSession::new_server(a);
        let client = MuxSession::new_client(b);

        spawn_echo_session(server.clone()).await;

        // 客户端打开流并 echo 回显
        let mut stream = client.open_stream().await.expect("open stream");
        stream.write_all(b"hello mux").await.unwrap();
        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("echo within timeout")
            .expect("read ok");
        assert_eq!(&buf[..n], b"hello mux");
    }

    #[tokio::test]
    async fn test_mux_session_concurrent_streams() {
        let (a, b) = duplex_pair().await;
        let server = MuxSession::new_server(a);
        let client = MuxSession::new_client(b);

        // 并发 8 条流：每条写入自己的序号，服务端原样回显
        spawn_echo_session(server).await;

        let mut handles = Vec::new();
        for i in 0..8u8 {
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                let mut stream = client.open_stream().await.expect("open stream");
                let payload = vec![i; 16];
                stream.write_all(&payload).await.unwrap();
                let mut buf = vec![0u8; 16];
                stream.read_exact(&mut buf).await.expect("read exact");
                assert_eq!(buf, payload);
            }));
        }
        for h in handles {
            h.await.expect("concurrent stream task");
        }
    }

    #[tokio::test]
    async fn test_mux_session_close_propagates() {
        let (a, b) = duplex_pair().await;
        let server = MuxSession::new_server(a);
        let client = MuxSession::new_client(b);

        // 客户端优雅关闭 → 服务端 accept 失败、会话标记关闭
        client.close().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(server.is_closed());
        assert!(server.accept_stream().await.is_err());
        assert!(client.open_stream().await.is_err());
    }

    #[tokio::test]
    async fn test_mux_session_peer_drop_closes() {
        let (a, b) = duplex_pair().await;
        let server = MuxSession::new_server(a);
        let client = MuxSession::new_client(b);
        let _ = b; // b 由 client 的 driver 持有，drop client 即断开

        // 客户端整体 drop（连接断开）→ driver 退出 → 服务端会话关闭
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(server.is_closed());
    }
}
