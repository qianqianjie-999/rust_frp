//! 工作连接管理：连接池、管理器与首字节分类

use rust_frp_core::Message;
use rust_frp_net::AnyConn;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};

use crate::*;

/// 工作连接管理器
pub struct WorkConnManager {
    /// 等待工作连接的通道 (proxy_name, sender)
    pending_conns: RwLock<std::collections::HashMap<String, mpsc::Sender<tokio::net::TcpStream>>>,
}

impl Default for WorkConnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkConnManager {
    pub fn new() -> Self {
        Self {
            pending_conns: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册一个等待工作连接的请求
    pub async fn register_pending(
        &self,
        proxy_name: String,
    ) -> mpsc::Receiver<tokio::net::TcpStream> {
        let (tx, rx) = mpsc::channel::<tokio::net::TcpStream>(1);
        let mut pending = self.pending_conns.write().await;
        pending.insert(proxy_name, tx);
        rx
    }

    /// 完成一个工作连接
    pub async fn complete_work_conn(
        &self,
        proxy_name: &str,
        work_conn: tokio::net::TcpStream,
    ) -> Result<(), String> {
        let pending = self.pending_conns.read().await;
        if let Some(sender) = pending.get(proxy_name) {
            sender
                .send(work_conn)
                .await
                .map_err(|e| format!("Failed to send work conn: {}", e))?;
            Ok(())
        } else {
            Err(format!(
                "No pending work conn request for proxy: {}",
                proxy_name
            ))
        }
    }
}

/// 服务器工作连接管理器（池模式）
/// 参考 frp 原版设计：预建工作连接池，访客到达时从池中取用。
/// 无 per-request 状态，自然杜绝僵尸条目和内存泄漏。
pub struct ServerWorkConnManager {
    /// 工作连接池 (proxy_name -> pool)
    pools: RwLock<std::collections::HashMap<String, Arc<WorkConnPool>>>,
    /// 每个代理的池大小
    pool_size: usize,
}

/// 池中的工作连接条目：明文连接 + 取出发完 StartWorkConn 后需应用的包装标志。
/// 压缩/加密包装必须在 StartWorkConn（明文 JSON）**之后**进行——客户端在读完
/// StartWorkConn 前不做任何包装，提前包装会让客户端把密文当 JSON 解析。
pub(crate) struct PooledWorkConn {
    pub(crate) conn: AnyConn,
    pub(crate) use_compression: bool,
    pub(crate) use_encryption: bool,
    /// 建立该工作连接时会话对应的 token 派生密钥。
    pub(crate) encryption_key: Option<Vec<u8>>,
    /// 连接入池时间；长空闲连接可能已被 NAT/中间设备静默丢弃。
    pub(crate) created_at: std::time::Instant,
}

impl PooledWorkConn {
    fn is_fresh_at(&self, now: std::time::Instant) -> bool {
        now.saturating_duration_since(self.created_at) < WORK_CONN_MAX_IDLE
    }
}

/// 工作连接在池中的最大闲置时间。
///
/// 线上已确认存在闲置 5h31m 后才取出的池连接：同批一条复位、一条仍可用。
/// 仅靠 FIN/RST 读探测无法覆盖 NAT/中间设备静默丢映射，因此在取出时同时
/// 施加有界池龄；超龄条目丢弃后按需新建，宁可多一次握手也不把死连接交给请求。
const WORK_CONN_MAX_IDLE: Duration = Duration::from_secs(30);

/// idle 工作连接取出后的读侧探测上限。
///
/// 健康连接此时尚未收到 StartWorkConn，读会保持 Pending；已收到 FIN/RST 的
/// 陈旧连接则会立即 Ready(EOF/error)。1ms 只用于捕获已排队的 socket 事件，
/// 不承担网络往返超时。
const WORK_CONN_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_millis(1);

/// 单条补池连接的等待上限；超时后结束本轮补池，等下个请求重新触发。
const WORK_CONN_REFILL_STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// 检查池中连接是否仍可用于发送 StartWorkConn。
///
/// 不能只依赖写入：TCP/TLS 对端已经关闭时，第一次 write 仍可能成功写入内核
/// 缓冲区，随后桥接才收到 ConnectionReset，造成偶发首个请求 502。
async fn pooled_work_conn_is_reusable(conn: &mut AnyConn) -> bool {
    let mut probe = [0u8; 1];
    match tokio::time::timeout(WORK_CONN_HEALTH_PROBE_TIMEOUT, conn.read(&mut probe)).await {
        Err(_) => true,
        Ok(Ok(0)) => false,
        Ok(Ok(_)) => {
            log::warn!("Discarding pooled work conn: unexpected data before StartWorkConn");
            false
        }
        Ok(Err(e)) => {
            log_work_conn_error(&e);
            false
        }
    }
}

/// 单个代理的工作连接池
pub(crate) struct WorkConnPool {
    state: Mutex<WorkConnPoolState>,
    capacity: usize,
    /// 同一时刻只允许一个补池任务，逐条补到容量上限。
    refilling: AtomicBool,
    fill_notify: Notify,
    next_waiter_id: std::sync::atomic::AtomicUsize,
}

struct WorkConnPoolState {
    idle: VecDeque<PooledWorkConn>,
    /// 每个并发取用请求独占一个等待槽，连接到达后直接投递。
    waiters: VecDeque<(usize, oneshot::Sender<PooledWorkConn>)>,
}

impl Default for ServerWorkConnManager {
    fn default() -> Self {
        Self::new(10)
    }
}

impl ServerWorkConnManager {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pools: RwLock::new(std::collections::HashMap::new()),
            pool_size,
        }
    }

    /// 为代理初始化工作连接池
    pub async fn init_pool(&self, proxy_name: &str) {
        let pool = Arc::new(WorkConnPool {
            state: Mutex::new(WorkConnPoolState {
                idle: VecDeque::new(),
                waiters: VecDeque::new(),
            }),
            capacity: self.pool_size,
            refilling: AtomicBool::new(false),
            fill_notify: Notify::new(),
            next_waiter_id: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut pools = self.pools.write().await;
        pools.insert(proxy_name.to_string(), pool);
        log::info!(
            "Initialized work conn pool for proxy: {}, capacity: {}",
            proxy_name,
            self.pool_size
        );
    }

    /// 注册工作连接到池中（由 process_work_conn 调用）
    /// 如果池已满，连接将被丢弃并关闭（背压保护）
    pub async fn register_work_conn(
        &self,
        proxy_name: &str,
        conn: AnyConn,
        use_compression: bool,
        use_encryption: bool,
        encryption_key: Option<Vec<u8>>,
    ) {
        global_metrics().incr_work_conn_total();
        let mut entry = Some(PooledWorkConn {
            conn,
            use_compression,
            use_encryption,
            encryption_key,
            created_at: std::time::Instant::now(),
        });
        let pools = self.pools.read().await;
        if let Some(pool) = pools.get(proxy_name) {
            let idle_added = {
                let mut state = pool.state.lock().await;
                loop {
                    if let Some((_, waiter)) = state.waiters.pop_front() {
                        match waiter.send(entry.take().expect("entry consumed twice")) {
                            Ok(()) => break Some(false),
                            Err(returned) => entry = Some(returned),
                        }
                    } else if state.idle.len() < pool.capacity
                        || (pool.refilling.load(Ordering::Acquire)
                            && state.idle.len() == pool.capacity)
                    {
                        state
                            .idle
                            .push_back(entry.take().expect("entry consumed twice"));
                        break Some(true);
                    } else {
                        break None;
                    }
                }
            };
            if idle_added.is_none() {
                log::warn!(
                    "Work conn pool full for {}, discarding and closing",
                    proxy_name
                );
                let _ = entry
                    .as_mut()
                    .expect("rejected entry missing")
                    .conn
                    .shutdown()
                    .await;
                return;
            }
            log::debug!("Work conn registered in pool for {}", proxy_name);
            if idle_added == Some(true) {
                pool.fill_notify.notify_waiters();
            }
        } else {
            log::warn!(
                "No pool initialized for proxy: {}, discarding and closing work conn",
                proxy_name
            );
            let _ = entry
                .as_mut()
                .expect("orphan entry missing")
                .conn
                .shutdown()
                .await;
        }
    }

    /// 启动唯一的补池任务：逐条请求连接，直到空闲池达到容量上限。
    ///
    /// 旧实现每次取用成功都独立发一条 `ReqWorkConn`；并发取用 N 条时会同时
    /// 请求 N 条补池连接，池满后多余的连接被关闭，客户端表现为 TLS EOF。
    fn schedule_refill(
        pool: Arc<WorkConnPool>,
        proxy_name: String,
        msg_tx: tokio::sync::mpsc::Sender<Message>,
    ) {
        if pool
            .refilling
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        tokio::spawn(async move {
            loop {
                let should_fill = {
                    let state = pool.state.lock().await;
                    state.waiters.is_empty() && state.idle.len() < pool.capacity
                };
                if !should_fill {
                    break;
                }

                let notified = pool.fill_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                    proxy_name: proxy_name.clone(),
                    ..Default::default()
                });
                if msg_tx.try_send(req).is_err() {
                    break;
                }
                if tokio::time::timeout(WORK_CONN_REFILL_STEP_TIMEOUT, notified)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            pool.refilling.store(false, Ordering::Release);
        });
    }

    /// 获取工作连接（供 TCP/HTTP/HTTPS/WebSocket 处理器调用）
    /// 与 frp 原版一致：从池中取 → 发 StartWorkConn，失败则重试 pool_size+1 次，
    /// 成功后立即补充一个请求保持池始终有可用连接。
    pub async fn get_work_conn(
        &self,
        proxy_name: &str,
        msg_tx: &tokio::sync::mpsc::Sender<Message>,
        timeout: Duration,
        visitor_addr: std::net::SocketAddr,
    ) -> Result<AnyConn, String> {
        // 获取代理的池（克隆 Arc，避免生命周期问题）
        let pool: Arc<WorkConnPool> = {
            let pools = self.pools.read().await;
            pools
                .get(proxy_name)
                .ok_or_else(|| format!("Pool not found for proxy: {}", proxy_name))?
                .clone()
        };

        let max_retries = self.pool_size + 1;
        let mut last_err = String::new();

        for retry in 0..max_retries {
            // 1. 从池中获取连接（池空则请求+等待）
            let mut entry = {
                let mut waiter = None;
                let mut waiter_id = 0;
                let available = {
                    let mut state = pool.state.lock().await;
                    state.idle.pop_front()
                };
                let entry = if let Some(entry) = available {
                    Some(entry)
                } else {
                    let (tx, rx) = oneshot::channel();
                    waiter_id = pool.next_waiter_id.fetch_add(1, Ordering::Relaxed);
                    waiter = Some(rx);
                    pool.state.lock().await.waiters.push_back((waiter_id, tx));
                    None
                };

                if let Some(entry) = entry {
                    entry
                } else {
                    log::debug!(
                        "Pool empty for {}, requesting new work conn (retry {}/{})",
                        proxy_name,
                        retry + 1,
                        max_retries
                    );
                    let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                        proxy_name: proxy_name.to_string(),
                        ..Default::default()
                    });
                    if let Err(e) = msg_tx.send(req).await {
                        pool.state
                            .lock()
                            .await
                            .waiters
                            .retain(|(id, _)| *id != waiter_id);
                        return Err(format!("Failed to send ReqWorkConn: {}", e));
                    }

                    match tokio::time::timeout(
                        timeout,
                        waiter.expect("empty pool must create a waiter"),
                    )
                    .await
                    {
                        Ok(Ok(entry)) => entry,
                        Ok(Err(_)) => return Err("Work conn waiter canceled".to_string()),
                        Err(_) => {
                            pool.state
                                .lock()
                                .await
                                .waiters
                                .retain(|(id, _)| *id != waiter_id);
                            return Err(format!(
                                "Timeout waiting for work conn for {}",
                                proxy_name
                            ));
                        }
                    }
                }
            };

            if !entry.is_fresh_at(std::time::Instant::now()) {
                log::debug!(
                    "Discarding expired pooled work conn for {} (retry {}/{})",
                    proxy_name,
                    retry + 1,
                    max_retries
                );
                continue;
            }

            if !pooled_work_conn_is_reusable(&mut entry.conn).await {
                log::debug!(
                    "Discarding stale pooled work conn for {} (retry {}/{})",
                    proxy_name,
                    retry + 1,
                    max_retries
                );
                continue;
            }

            // 2. 明文发送 StartWorkConn 唤醒客户端（携带访问者地址，用于 PROXY protocol）
            //    客户端读完该消息后才开始包装压缩/加密，服务端也必须在此之后才包装
            let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                error: "".to_string(),
                src_addr: visitor_addr.ip().to_string(),
                src_port: visitor_addr.port(),
                dst_addr: "127.0.0.1".to_string(),
                dst_port: 0,
            });
            match rust_frp_core::write_message(&mut entry.conn, &resp).await {
                Ok(_) => {
                    // 3. 握手完成，按固定顺序包装 —— 先压缩（内层）、后加密（外层）
                    let mut conn = entry.conn;
                    if entry.use_compression {
                        log::debug!(
                            "Work conn compression (snappy) enabled for proxy: {}",
                            proxy_name
                        );
                        conn = Box::new(rust_frp_net::compress::CompressedStream::new(conn));
                    }
                    if entry.use_encryption {
                        match entry.encryption_key {
                            Some(key) => {
                                conn = Box::new(
                                    rust_frp_net::crypto::EncryptedStream::new(conn, &key)
                                        .map_err(|e| format!("wrap encryption: {}", e))?,
                                );
                            }
                            None => {
                                // fail-closed：客户端请求加密但服务端未配 token
                                let _ = conn.shutdown().await;
                                return Err(format!(
                                    "proxy {} requests use_encryption but server has no token",
                                    proxy_name
                                ));
                            }
                        }
                    }
                    Self::schedule_refill(pool.clone(), proxy_name.to_string(), msg_tx.clone());
                    return Ok(conn);
                }
                Err(e) => {
                    last_err = format!("Failed to send StartWorkConn: {}", e);
                    log::warn!(
                        "{} for proxy {} (retry {}/{})",
                        last_err,
                        proxy_name,
                        retry + 1,
                        max_retries
                    );
                    // 连接已损坏，丢弃，继续重试
                    drop(entry);
                }
            }
        }

        Err(format!(
            "All {} retries exhausted for {}: {}",
            max_retries, proxy_name, last_err
        ))
    }

    /// 移除代理的池（代理停止时调用）
    pub async fn remove_pool(&self, proxy_name: &str) {
        let mut pools = self.pools.write().await;
        pools.remove(proxy_name);
        log::info!("Removed work conn pool for {}", proxy_name);
    }
}

/// 工作连接首字节分类结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkConnClass {
    /// 客户端发起 TLS 握手（首字节 0x16）且服务器已配置 TLS
    Tls,
    /// 明文协议（兼容旧客户端）
    Plain,
    /// 拒绝连接
    Reject,
}

/// 根据首字节判定工作连接处理方式
///
/// - `first_byte == 0x16`：TLS ClientHello，服务器配置了 TLS 则走 TLS，
///   未配置则无法完成握手只能拒绝
/// - 其他字节：明文协议；tls_only 模式下拒绝（防止降级）
pub fn classify_work_conn(first_byte: u8, tls_available: bool, tls_only: bool) -> WorkConnClass {
    match (first_byte == 0x16, tls_available, tls_only) {
        (true, true, _) => WorkConnClass::Tls,
        (true, false, _) => WorkConnClass::Reject,
        (false, _, true) => WorkConnClass::Reject,
        (false, _, false) => WorkConnClass::Plain,
    }
}

/// 工作连接错误日志（对端断开类错误降级为 debug，避免日志噪音）
pub(crate) fn log_work_conn_error(e: &(dyn std::error::Error + Send + Sync)) {
    let msg = e.to_string().to_lowercase();
    if msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("broken pipe")
    {
        log::debug!("Work connection closed (peer disconnected): {:?}", e);
    } else {
        log::error!("Failed to process work connection: {:?}", e);
    }
}

#[cfg(test)]
mod pool_health_tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct StaleConn {
        addr: std::net::SocketAddr,
        writes: Arc<AtomicUsize>,
    }

    impl AsyncRead for StaleConn {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // 已关闭的对端：读取立即返回 EOF。
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for StaleConn {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // 残留连接在首次写入时仍可能成功，这正是不能只靠写失败判活的原因。
            self.writes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait::async_trait]
    impl rust_frp_net::FrpConn for StaleConn {
        fn remote_addr(&self) -> Option<std::net::SocketAddr> {
            Some(self.addr)
        }
    }

    struct LiveConn {
        addr: std::net::SocketAddr,
    }

    impl AsyncRead for LiveConn {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // StartWorkConn 前的健康连接没有应用数据可读。
            Poll::Pending
        }
    }

    impl AsyncWrite for LiveConn {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait::async_trait]
    impl rust_frp_net::FrpConn for LiveConn {
        fn remote_addr(&self) -> Option<std::net::SocketAddr> {
            Some(self.addr)
        }
    }

    #[test]
    fn pooled_work_conn_expires_after_max_idle() {
        let now = std::time::Instant::now();
        let entry = PooledWorkConn {
            conn: Box::new(LiveConn {
                addr: "127.0.0.1:41003".parse().unwrap(),
            }),
            use_compression: false,
            use_encryption: false,
            encryption_key: None,
            created_at: now - WORK_CONN_MAX_IDLE,
        };

        assert!(!entry.is_fresh_at(now));
        assert!(entry.is_fresh_at(now - Duration::from_millis(1)));
    }

    /// 生产回归：池中的工作连接可能在对端关闭很久后才被取出。
    /// 首次写不一定失败，因此必须在发送 StartWorkConn 前探测读侧 EOF，
    /// 丢弃陈旧条目并重新请求一条连接。
    #[tokio::test]
    async fn get_work_conn_discards_stale_pooled_conn() {
        let manager = Arc::new(ServerWorkConnManager::new(1));
        manager.init_pool("web_regression").await;

        let stale_addr: std::net::SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let fresh_addr: std::net::SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let stale_writes = Arc::new(AtomicUsize::new(0));
        manager
            .register_work_conn(
                "web_regression",
                Box::new(StaleConn {
                    addr: stale_addr,
                    writes: stale_writes.clone(),
                }),
                false,
                false,
                None,
            )
            .await;

        let (msg_tx, mut msg_rx) = mpsc::channel(4);
        let responder_manager = manager.clone();
        let responder = tokio::spawn(async move {
            let request = msg_rx.recv().await.expect("expected ReqWorkConn");
            match request {
                Message::ReqWorkConn(request) => {
                    assert_eq!(request.proxy_name, "web_regression");
                }
                other => panic!("expected ReqWorkConn, got {other:?}"),
            }
            responder_manager
                .register_work_conn(
                    "web_regression",
                    Box::new(LiveConn { addr: fresh_addr }),
                    false,
                    false,
                    None,
                )
                .await;
        });

        let visitor_addr: std::net::SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let conn = tokio::time::timeout(
            Duration::from_secs(1),
            manager.get_work_conn(
                "web_regression",
                &msg_tx,
                Duration::from_secs(1),
                visitor_addr,
            ),
        )
        .await
        .expect("get_work_conn timed out")
        .expect("get_work_conn failed");

        responder.abort();
        assert_eq!(conn.remote_addr(), Some(fresh_addr));
        assert_eq!(
            stale_writes.load(Ordering::SeqCst),
            0,
            "stale pooled conn must be discarded before StartWorkConn"
        );
    }

    #[tokio::test]
    async fn get_work_conn_discards_peer_closed_tcp_conn_repeatedly() {
        for round in 0..32 {
            let manager = Arc::new(ServerWorkConnManager::new(1));
            manager.init_pool("tcp_regression").await;

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind stale TCP listener");
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .expect("connect stale TCP peer");
            let (stale_server, _) = listener.accept().await.expect("accept stale TCP peer");
            drop(client);

            manager
                .register_work_conn("tcp_regression", Box::new(stale_server), false, false, None)
                .await;

            let fresh_addr: std::net::SocketAddr =
                format!("127.0.0.1:{}", 42000 + round).parse().unwrap();
            let (msg_tx, mut msg_rx) = mpsc::channel(4);
            let responder_manager = manager.clone();
            let responder = tokio::spawn(async move {
                let request = msg_rx.recv().await.expect("expected ReqWorkConn");
                assert!(matches!(request, Message::ReqWorkConn(_)));
                responder_manager
                    .register_work_conn(
                        "tcp_regression",
                        Box::new(LiveConn { addr: fresh_addr }),
                        false,
                        false,
                        None,
                    )
                    .await;
            });

            let visitor_addr: std::net::SocketAddr = "127.0.0.1:50001".parse().unwrap();
            let conn = tokio::time::timeout(
                Duration::from_secs(1),
                manager.get_work_conn(
                    "tcp_regression",
                    &msg_tx,
                    Duration::from_secs(1),
                    visitor_addr,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("round {round}: get_work_conn timed out"))
            .unwrap_or_else(|e| panic!("round {round}: get_work_conn failed: {e}"));

            responder.abort();
            assert_eq!(
                conn.remote_addr(),
                Some(fresh_addr),
                "round {round}: returned a peer-closed TCP conn"
            );
        }
    }

    /// 生产回归：`get_work_conn` 高并发时，每个成功取用都会独立补池，
    /// 导致补池请求互相竞争并超过池容量。对 pool_size=10、并发取 40 条连接，
    /// 最多应请求 40 条业务连接 + 10 条空闲补池连接；旧实现会请求约 80 条，
    /// 多出的连接因池满被关闭，并在客户端形成 TLS EOF。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_acquisitions_do_not_overfill_pool() {
        const POOL_SIZE: usize = 10;
        const ACQUISITIONS: usize = 40;

        let manager = Arc::new(ServerWorkConnManager::new(POOL_SIZE));
        manager.init_pool("burst_pool").await;

        let (msg_tx, mut msg_rx) = mpsc::channel(256);
        let request_count = Arc::new(AtomicUsize::new(0));
        let responder_manager = manager.clone();
        let responder_requests = request_count.clone();
        let responder = tokio::spawn(async move {
            let mut next_addr = 43_000u16;
            while let Some(message) = msg_rx.recv().await {
                match message {
                    Message::ReqWorkConn(request) => {
                        assert_eq!(request.proxy_name, "burst_pool");
                        responder_requests.fetch_add(1, Ordering::SeqCst);
                        let addr = format!("127.0.0.1:{next_addr}").parse().unwrap();
                        next_addr = next_addr.wrapping_add(1);
                        responder_manager
                            .register_work_conn(
                                "burst_pool",
                                Box::new(LiveConn { addr }),
                                false,
                                false,
                                None,
                            )
                            .await;
                    }
                    other => panic!("expected ReqWorkConn, got {other:?}"),
                }
            }
        });

        let mut tasks = Vec::with_capacity(ACQUISITIONS);
        for i in 0..ACQUISITIONS {
            let manager = manager.clone();
            let msg_tx = msg_tx.clone();
            tasks.push(tokio::spawn(async move {
                let visitor_addr: std::net::SocketAddr =
                    format!("127.0.0.1:{}", 50_000 + i).parse().unwrap();
                manager
                    .get_work_conn("burst_pool", &msg_tx, Duration::from_secs(2), visitor_addr)
                    .await
                    .map(|_| ())
            }));
        }

        for (index, task) in tasks.into_iter().enumerate() {
            let result = tokio::time::timeout(Duration::from_secs(3), task).await;
            if !matches!(result, Ok(Ok(Ok(())))) {
                let pool = manager
                    .pools
                    .read()
                    .await
                    .get("burst_pool")
                    .expect("pool missing")
                    .clone();
                let state = pool.state.lock().await;
                let requested = request_count.load(Ordering::SeqCst);
                panic!(
                    "concurrent get_work_conn task {index} failed: result={result:?}, \
                     requested={requested}, idle={}, waiters={}",
                    state.idle.len(),
                    state.waiters.len()
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let requested = request_count.load(Ordering::SeqCst);
        responder.abort();

        assert!(
            requested <= ACQUISITIONS + POOL_SIZE,
            "work conn overfill: requested={requested}, expected <= {}",
            ACQUISITIONS + POOL_SIZE
        );
    }

    /// 补池请求已经发出后，业务响应可能先把空闲池填满。此时迟到的补池响应
    /// 不应被当作无主连接丢弃；允许它作为唯一一条在途余量落池，随后补池任务
    /// 观察到池已满会自然停止。
    #[tokio::test]
    async fn in_flight_refill_is_not_dropped_when_idle_pool_was_filled() {
        let manager = Arc::new(ServerWorkConnManager::new(1));
        manager.init_pool("refill_race").await;

        manager
            .register_work_conn(
                "refill_race",
                Box::new(LiveConn {
                    addr: "127.0.0.1:44001".parse().unwrap(),
                }),
                false,
                false,
                None,
            )
            .await;

        let pool = manager
            .pools
            .read()
            .await
            .get("refill_race")
            .expect("pool missing")
            .clone();
        pool.refilling.store(true, Ordering::Release);

        manager
            .register_work_conn(
                "refill_race",
                Box::new(LiveConn {
                    addr: "127.0.0.1:44002".parse().unwrap(),
                }),
                false,
                false,
                None,
            )
            .await;

        assert_eq!(
            pool.state.lock().await.idle.len(),
            2,
            "the single in-flight refill must be retained instead of closed"
        );
    }

    /// 业务连接直接交给等待者后，不应唤醒补池循环。否则补池循环会把
    /// 业务连接的到达误判成自己的补池响应，提前再发一条 `ReqWorkConn`。
    #[tokio::test]
    async fn waiter_delivery_does_not_wake_refill_loop() {
        let manager = Arc::new(ServerWorkConnManager::new(1));
        manager.init_pool("notify_race").await;
        let pool = manager
            .pools
            .read()
            .await
            .get("notify_race")
            .expect("pool missing")
            .clone();

        let (waiter_tx, waiter_rx) = oneshot::channel();
        pool.state.lock().await.waiters.push_back((1, waiter_tx));

        let notified = pool.fill_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        manager
            .register_work_conn(
                "notify_race",
                Box::new(LiveConn {
                    addr: "127.0.0.1:44003".parse().unwrap(),
                }),
                false,
                false,
                None,
            )
            .await;

        assert!(
            tokio::time::timeout(Duration::from_millis(50), notified)
                .await
                .is_err(),
            "delivery to a business waiter must not wake the refill loop"
        );
        assert!(
            waiter_rx.await.is_ok(),
            "the business waiter must receive the connection"
        );
    }
}
