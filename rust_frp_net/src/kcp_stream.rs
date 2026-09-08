//! # KCP over UDP 异步流（XTCP P2P 通道）
//!
//! 将同步的 `kcp` crate 封装为 tokio 异步流，用于 XTCP 打洞成功后的
//! P2P 可靠传输：
//!
//! 1. **一 socket 一会话**：每次打洞使用独立 UDP socket，无需 conv 路由。
//! 2. **发起方**（visitor）`KcpStream::connect`：指定 conv，主动向候选地址发送；
//!    **应答方**（proxy owner）`KcpStream::accept`：`input_conv()` 从首个输入学习 conv。
//! 3. **打洞包**：`PUNCH_PACKET`（14 字节 < KCP 头 24 字节，对端 kcp 输入自动忽略），
//!    由内置 punch 任务周期发送，直到锁定对端或流关闭。
//! 4. **多候选地址**：NAT 公网地址 + 本地局域网地址同时尝试，
//!    首个有效 KCP 输入到达后锁定唯一对端。
//! 5. **死链检测**：`set_maximum_resend_times` 超限后 `is_dead_link()`，
//!    读返回 EOF、写返回 BrokenPipe。
//!
//! ## 内部任务（均持有 Weak 引用，流释放后自动退出）
//!
//! - recv 循环：`socket.recv_from` → 打洞包应答 / `kcp.input` + 立即冲刷快速 ACK
//! - update 心跳：每 20ms `kcp.update` 冲刷发送缓冲（ACK / 重传 / 窗口探测）
//! - punch 任务：对端锁定前每 100ms 向所有候选地址发送打洞包

use crate::{FrpConn, NetError};
use kcp::{Kcp, KCP_OVERHEAD};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

/// UDP 打洞探测包（14 字节 < KCP 头 24 字节，kcp 输入侧自动忽略）
const PUNCH_PACKET: &[u8] = b"rfrp-udp-punch";
/// KCP 带内握手段标记（connect 侧发出，accept 侧学习 conv 后透明丢弃）。
///
/// KCP 无连接握手，打洞阶段双方都不发业务数据会互相等待死锁；
/// connect 侧主动发送单字节握手包，驱动 accept 侧 `input_conv` 学习 conv
/// 并回复 ACK，打洞得以在业务数据到达前建立。
const HANDSHAKE_MAGIC: u8 = 0x1F;
/// update 心跳周期
const TICK_INTERVAL: Duration = Duration::from_millis(20);
/// 打洞包发送周期
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// recv 循环检查流存活的周期（Weak 升级失败即退出）
const RECV_CHECK_INTERVAL: Duration = Duration::from_millis(500);

/// KCP 输出收集器：flush 期间 kcp 每次回调写入一个独立 UDP 包，
/// 保留包边界，随后由外层逐个经 UDP 发送
#[derive(Clone, Default)]
struct UdpOutput(Arc<Mutex<Vec<Vec<u8>>>>);

impl std::io::Write for UdpOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct KcpState {
    kcp: Kcp<UdpOutput>,
    out: Arc<Mutex<Vec<Vec<u8>>>>,
    /// 候选对端地址（公网 + 本地）
    peers: Vec<SocketAddr>,
    /// 首个有效 KCP 输入后锁定的对端
    active_peer: Option<SocketAddr>,
    epoch: Instant,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// 收到过有效 KCP 输入
    active: bool,
    /// 死链 / 致命错误
    dead: bool,
    /// accept 侧：首次读出的握手字节待丢弃
    consume_handshake: bool,
}

impl KcpState {
    fn now_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis() as u32
    }
}

struct Shared {
    state: Mutex<KcpState>,
    socket: Arc<UdpSocket>,
    closed: AtomicBool,
}

impl Shared {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn wake_read(st: &mut KcpState) {
        if let Some(w) = st.read_waker.take() {
            w.wake();
        }
    }

    fn wake_write(st: &mut KcpState) {
        if let Some(w) = st.write_waker.take() {
            w.wake();
        }
    }

    fn mark_dead(&self) {
        let mut st = self.state.lock().unwrap();
        st.dead = true;
        Self::wake_read(&mut st);
        Self::wake_write(&mut st);
    }

    fn peers_of(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().peers.clone()
    }

    /// 冲刷 kcp 发送缓冲并经 UDP 发出
    fn flush_and_send(&self) {
        let pkts = {
            let mut st = self.state.lock().unwrap();
            if st.dead {
                return;
            }
            let now = st.now_ms();
            if let Err(e) = st.kcp.update(now) {
                log::debug!("kcp update error: {}", e);
                st.dead = true;
                Self::wake_read(&mut st);
                Self::wake_write(&mut st);
                return;
            }
            let mut out = st.out.lock().unwrap();
            out.drain(..).collect::<Vec<Vec<u8>>>()
        };
        send_all(&self.socket, &pkts, self);
    }
}

/// 向锁定对端（或全部候选地址）同步发送分组
///
/// UDP 发送失败不视为致命：打洞阶段目标端口可能尚未就绪，
/// 数据仍留在 kcp 发送队列，由 update 心跳周期重传。
fn send_all(socket: &Arc<UdpSocket>, pkts: &[Vec<u8>], shared: &Shared) {
    let target = {
        let st = shared.state.lock().unwrap();
        if st.dead {
            return;
        }
        st.active_peer.clone()
    };
    for pkt in pkts {
        match &target {
            Some(peer) => {
                if let Err(e) = socket.try_send_to(pkt, *peer) {
                    log::debug!("kcp udp send to {} failed: {}", peer, e);
                }
            }
            None => {
                let peers = shared.peers_of();
                for p in peers {
                    if let Err(e) = socket.try_send_to(pkt, p) {
                        log::debug!("kcp udp send to {} failed: {}", p, e);
                    }
                }
            }
        }
    }
}

/// KCP over UDP 异步流
pub struct KcpStream {
    shared: Arc<Shared>,
}

impl KcpStream {
    /// 发起方：指定 conv，主动向候选地址发送
    pub async fn connect(
        socket: Arc<UdpSocket>,
        peers: Vec<SocketAddr>,
        conv: u32,
    ) -> Result<Self, NetError> {
        Self::new(socket, peers, Some(conv)).await
    }

    /// 应答方：conv 从首个有效输入学习
    pub async fn accept(socket: Arc<UdpSocket>, peers: Vec<SocketAddr>) -> Result<Self, NetError> {
        Self::new(socket, peers, None).await
    }

    async fn new(
        socket: Arc<UdpSocket>,
        mut peers: Vec<SocketAddr>,
        conv: Option<u32>,
    ) -> Result<Self, NetError> {
        if peers.is_empty() {
            return Err(NetError::Other("no peer addresses".into()));
        }
        peers.dedup();

        let out = Arc::new(Mutex::new(Vec::new()));
        let mut kcp = match conv {
            Some(c) => Kcp::new_stream(c, UdpOutput(out.clone())),
            None => {
                let mut k = Kcp::new_stream(0, UdpOutput(out.clone()));
                k.input_conv(); // 应答方：conv 从首个输入学习
                k
            }
        };
        // 快速模式（对齐 frp kcp 配置：nodelay + 无拥塞控制）
        kcp.set_nodelay(true, 50, 1, true);
        kcp.set_wndsize(128, 128);
        kcp.set_mtu(1200)
            .map_err(|e| NetError::Other(e.to_string()))?;
        kcp.set_maximum_resend_times(20);

        let is_connect = conv.is_some();
        let shared = Arc::new(Shared {
            state: Mutex::new(KcpState {
                kcp,
                out,
                peers: peers.clone(),
                active_peer: None,
                epoch: Instant::now(),
                read_waker: None,
                write_waker: None,
                active: false,
                dead: false,
                consume_handshake: !is_connect,
            }),
            socket: socket.clone(),
            closed: AtomicBool::new(false),
        });

        spawn_recv_loop(Arc::downgrade(&shared));
        spawn_ticker(Arc::downgrade(&shared));
        spawn_puncher(Arc::downgrade(&shared));

        if is_connect {
            // connect 侧：立即发送带内握手字节驱动对端 conv 学习与 ACK，
            // 未获 ACK 前由 kcp 重传 + puncher 持续打洞，直到对端可达
            let pkts = {
                let mut st = shared.state.lock().unwrap();
                let _ = st.kcp.send(&[HANDSHAKE_MAGIC]);
                let now = st.now_ms();
                let _ = st.kcp.update(now);
                let mut out = st.out.lock().unwrap();
                out.drain(..).collect::<Vec<Vec<u8>>>()
            };
            for pkt in &pkts {
                for p in &peers {
                    let _ = socket.try_send_to(pkt, *p);
                }
            }
        }

        Ok(Self { shared })
    }

    /// 是否收到过对端有效 KCP 输入（打洞成功标志）
    pub fn has_activity(&self) -> bool {
        self.shared.state.lock().unwrap().active
    }

    /// 当前锁定的对端地址
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.shared.state.lock().unwrap().active_peer
    }

    /// 关闭流并停止全部后台任务
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Relaxed);
        let mut st = self.shared.state.lock().unwrap();
        Shared::wake_read(&mut st);
        Shared::wake_write(&mut st);
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 循环读取：accept 侧可能先读到单字节握手段（丢弃后需继续读，
        // 不能返回空读——AsyncRead 返回 0 会被解释为 EOF）
        loop {
            let mut st = self.shared.state.lock().unwrap();
            if st.dead || self.shared.is_closed() {
                return Poll::Ready(Ok(())); // EOF
            }
            let mut out = vec![0u8; buf.remaining().max(1)];
            match st.kcp.recv(&mut out) {
                Ok(n) => {
                    let start = if n >= 1 && st.consume_handshake {
                        st.consume_handshake = false;
                        if out[0] == HANDSHAKE_MAGIC {
                            1 // 跳过握手段
                        } else {
                            0 // 首字节非握手标记（对端未发握手），按正常数据处理
                        }
                    } else {
                        0
                    };
                    if start < n {
                        buf.put_slice(&out[start..n]);
                        return Poll::Ready(Ok(()));
                    }
                    // n == 1 且为握手：丢弃后继续读下一段
                }
                Err(kcp::Error::RecvQueueEmpty) => {
                    st.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )))
                }
            }
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let shared = &self.shared;
        let mut st = shared.state.lock().unwrap();
        if st.dead || shared.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "kcp stream closed",
            )));
        }
        // 发送窗口背压：待确认分段达到窗口大小时等待 ACK 后重试
        if st.kcp.wait_snd() >= st.kcp.snd_wnd() as usize {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // kcp 单次 send 的分片数必须 < 接收窗口（128），限制每次送入字节数
        let max_chunk = st.kcp.mss() * 64;
        let end = buf.len().min(max_chunk);
        match st.kcp.send(&buf[..end]) {
            Ok(n) => {
                // update 更新时钟并按 interval 冲刷；新数据必须立即发出，
                // 不能等下一个 flush 窗口（update 内有 ts_flush 时间门控），
                // 否则短连接可能在数据段发出前就结束
                let now = st.now_ms();
                if let Err(e) = st.kcp.update(now).and_then(|_| st.kcp.flush()) {
                    st.dead = true;
                    Shared::wake_read(&mut st);
                    Shared::wake_write(&mut st);
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )));
                }
                let pkts: Vec<Vec<u8>> = st.out.lock().unwrap().drain(..).collect();
                drop(st);
                send_all(&shared.socket, &pkts, shared);
                Poll::Ready(Ok(n))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shared.flush_and_send();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

#[async_trait::async_trait]
impl FrpConn for KcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr()
    }
}

/// recv 循环：打洞包应答 / kcp 输入 + 立即冲刷快速 ACK
fn spawn_recv_loop(weak: Weak<Shared>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Some(shared) = weak.upgrade() else { break };
            if shared.is_closed() {
                break;
            }
            let socket = shared.socket.clone();
            drop(shared);
            let (n, src) = tokio::select! {
                res = socket.recv_from(&mut buf) => match res {
                    Ok(v) => v,
                    Err(_) => break,
                },
                _ = tokio::time::sleep(RECV_CHECK_INTERVAL) => continue,
            };
            let Some(shared) = weak.upgrade() else { break };
            if shared.is_closed() {
                break;
            }
            let data = &buf[..n];

            if data == PUNCH_PACKET {
                // 打洞包：原样应答，帮助对端 NAT 放行本方地址
                let _ = socket.try_send_to(PUNCH_PACKET, src);
                continue;
            }
            if data.len() < KCP_OVERHEAD as usize {
                continue; // 无效短包
            }

            let got_data = {
                let mut st = shared.state.lock().unwrap();
                if st.dead {
                    continue;
                }
                match st.kcp.input(data) {
                    Ok(_) => {
                        st.active = true;
                        st.active_peer.get_or_insert(src);
                        true
                    }
                    Err(kcp::Error::ConvInconsistent(_, _)) => false, // 其他会话的包
                    Err(e) => {
                        log::trace!("kcp input error: {}", e);
                        false
                    }
                }
            };
            if got_data {
                shared.flush_and_send(); // 立即 ACK
                let mut st = shared.state.lock().unwrap();
                Shared::wake_read(&mut st);
            }
        }
    });
}

/// update 心跳：周期冲刷 kcp 发送缓冲（ACK / 重传 / 窗口探测）
fn spawn_ticker(weak: Weak<Shared>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            let Some(shared) = weak.upgrade() else { break };
            if shared.is_closed() {
                break;
            }
            let dead_link = {
                let st = shared.state.lock().unwrap();
                st.kcp.is_dead_link() && !st.dead
            };
            if dead_link {
                log::debug!("kcp dead link detected");
                shared.mark_dead();
                break;
            }
            shared.flush_and_send();
            // 释放写背压（发送队列被 ACK 清空后唤醒阻塞的写）
            let mut st = shared.state.lock().unwrap();
            if st.kcp.wait_snd() < st.kcp.snd_wnd() as usize {
                Shared::wake_write(&mut st);
            }
        }
    });
}

/// 打洞任务：对端锁定前周期向所有候选地址发送打洞包
fn spawn_puncher(weak: Weak<Shared>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(PUNCH_INTERVAL).await;
            let Some(shared) = weak.upgrade() else { break };
            if shared.is_closed() {
                break;
            }
            let locked = shared.state.lock().unwrap().active_peer.is_some();
            if locked {
                break; // 已连通，停止打洞
            }
            for p in shared.peers_of() {
                let _ = shared.socket.try_send_to(PUNCH_PACKET, p);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn bind_pair() -> (Arc<UdpSocket>, Arc<UdpSocket>, SocketAddr, SocketAddr) {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let aa = a.local_addr().unwrap();
        let bb = b.local_addr().unwrap();
        (a, b, aa, bb)
    }

    /// 回环：发起方 ↔ 应答方 双向收发
    #[tokio::test]
    async fn test_kcp_loopback_echo() {
        let (a, b, aa, bb) = bind_pair().await;

        let mut client = KcpStream::connect(a, vec![bb], 0x1234_5678).await.unwrap();
        let mut server = KcpStream::accept(b, vec![aa]).await.unwrap();

        // client -> server
        client.write_all(b"hello kcp").await.unwrap();

        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), server.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello kcp");

        // server -> client（反向）
        server.write_all(b"pong!").await.unwrap();
        let mut buf2 = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut buf2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf2, b"pong!");

        assert!(client.has_activity());
        assert_eq!(client.peer_addr(), Some(bb));
        assert_eq!(server.peer_addr(), Some(aa));
    }

    /// 大块数据传输（触发分片、滑动窗口与 ACK 路径）
    #[tokio::test]
    async fn test_kcp_large_transfer() {
        let (a, b, aa, bb) = bind_pair().await;
        let mut client = KcpStream::connect(a, vec![bb], 42).await.unwrap();
        let mut server = KcpStream::accept(b, vec![aa]).await.unwrap();

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let writer = tokio::spawn(async move {
            let mut client = client;
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            // 保持 stream 存活直到对端收完（drop 会关闭 KCP 会话丢弃未发数据）
            let _ = done_rx.await;
        });

        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(60), server.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        let _ = done_tx.send(());
        writer.await.unwrap();
        assert_eq!(got, expected);
    }

    /// 打洞包不干扰 KCP 数据（punch 任务运行期间正常收发）
    #[tokio::test]
    async fn test_punch_packet_ignored() {
        let (a, b, aa, bb) = bind_pair().await;
        let mut client = KcpStream::connect(a, vec![bb], 7).await.unwrap();
        let mut server = KcpStream::accept(b, vec![aa]).await.unwrap();

        // 等打洞任务至少跑一轮
        tokio::time::sleep(Duration::from_millis(200)).await;

        client.write_all(b"data-after-punch").await.unwrap();
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_secs(10), server.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"data-after-punch");
    }

    /// 空候选地址报错
    #[tokio::test]
    async fn test_no_peers_error() {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        assert!(KcpStream::connect(a, vec![], 1).await.is_err());
    }
}
