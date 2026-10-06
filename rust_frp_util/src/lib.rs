//! FRP 工具函数模块
//!
//! 该模块提供了 FRP 项目中常用的工具函数，包括：
//!
//! ## 主要功能
//!
//! 1. **时间戳获取与格式化**
//!    - `get_timestamp()`: 获取当前 Unix 时间戳（秒）
//!    - `localtime::format_local_datetime()`: Unix 秒 → 本地时区时间字符串
//!
//! 2. **地址解析**
//!    - `parse_addr()`: 将地址字符串解析为 SocketAddr
//!    - 支持域名解析
//!
//! 3. **随机 ID 生成**
//!    - `rand_id()`: 生成指定长度的随机字符串
//!    - 用于生成唯一的 run_id、client_id 等标识符
//!
//! 4. **连接桥接**
//!    - `bridge_connections()`: 桥接两个 TCP 连接，实现双向数据转发
//!    - `bridge_streams()`: 桥接任意两个异步流，支持更广泛的类型
//!
//! 5. **重试机制**
//!    - `retry()`: 执行带重试的操作
//!    - 支持指数退避策略
//!    - 可配置最大重试次数和延迟
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! // 生成随机 ID
//! let run_id = rand_id(16);
//!
//! // 桥接两个连接
//! bridge_connections(conn1, conn2).await?;
//!
//! // 带重试的操作
//! let result = retry(&config, "connect", || async {
//!     connect_to_server().await
//! }).await?;
//! ```
//!
//! ## 安全性
//!
//! - 随机 ID 使用安全的随机数生成器
//! - 连接桥接保证数据完整性

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

/// 工具模块错误类型
#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    /// I/O 错误
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// 无效地址错误
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

/// 获取当前时间戳（秒）
pub fn get_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX_EPOCH (1970)")
        .as_secs() as i64
}

/// 解析地址字符串为 SocketAddr
pub fn parse_addr(addr: &str) -> Result<SocketAddr, std::io::Error> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid address"))
}

/// 常量时间字节比较（用于 token / 签名 / 密钥等敏感数据比较）
///
/// 通过 XOR 累积差异避免提前返回，防止 timing 攻击推断内容。
/// 注意：长度不等时立即返回 false，会泄露长度信息——对 token 比较而言可接受
/// （ring 0.16 的 `constant_time::verify_slices_are_equal` 行为一致）。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 生成随机 ID
pub fn rand_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// 桥接两个 TCP 连接，实现双向数据转发
pub async fn bridge_connections(
    conn1: tokio::net::TcpStream,
    conn2: tokio::net::TcpStream,
) -> Result<(), std::io::Error> {
    let (mut r1, mut w1) = tokio::io::split(conn1);
    let (mut r2, mut w2) = tokio::io::split(conn2);

    let s_to_c = tokio::io::copy(&mut r1, &mut w2);
    let c_to_s = tokio::io::copy(&mut r2, &mut w1);

    tokio::select! {
        r = s_to_c => { r.map(|_| ())?; }
        r = c_to_s => { r.map(|_| ())?; }
    }

    let _ = w1.shutdown().await;
    let _ = w2.shutdown().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_timestamp() {
        let ts1 = get_timestamp();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let ts2 = get_timestamp();
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_rand_id_length() {
        let id = rand_id(16);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_rand_id_uniqueness() {
        let id1 = rand_id(32);
        let id2 = rand_id(32);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_rand_id_zero_length() {
        let id = rand_id(0);
        assert_eq!(id.len(), 0);
    }

    #[test]
    fn test_rand_id_alphanumeric() {
        let id = rand_id(100);
        for c in id.chars() {
            assert!(c.is_ascii_alphanumeric());
        }
    }

    #[test]
    fn test_parse_addr_valid() {
        let addr = parse_addr("127.0.0.1:8080").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_addr_invalid() {
        assert!(parse_addr("invalid_address").is_err());
    }
}

/// 桥接任意两个双向流，实现双向数据转发
/// 支持 TcpStream、TLS stream 等任何实现 AsyncRead + AsyncWrite 的类型
pub async fn bridge_streams<S1, S2>(
    stream1: S1,
    stream2: S2,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    bridge_streams_counted(stream1, stream2).await.map(|_| ())
}

/// 桥接半关闭宽限期：一侧已读到 EOF 后，等待另一侧结束的最长时间。
///
/// # 为什么需要它（修 fd 泄漏）
///
/// `tokio::io::copy_bidirectional` 只在**两个方向都 EOF** 后才返回。对端若
/// "半关闭后不再发 FIN"（扫描器/健康检查的典型行为：发完请求就挂着不关连接），
/// 桥接任务会**永久挂起** —— visitor 侧 fd 不释放、socket 永久停在 `FIN-WAIT-2`
/// （`ss -s` 的 `orphaned 0` 即证据），累积可打满 fd 上限、`accept()` 失败，
/// 且 `Restart=always` 因进程未退出而不会自愈。
///
/// # 为什么不是"空闲超时 / 总时长超时"
///
/// 线上有 300s 长请求（procurement）与 50MB 上传（ARMS），SSH/WebSocket 会话也会
/// 长时间无数据 —— 任何"按空闲计时"的超时都会误杀它们。本计时**只在某一方向
/// 已经 EOF 之后才启动**，因此只要双向都还活着（含上述全部场景）就完全不受影响，
/// 只回收"已经半死"的连接。
///
/// # 300s 的取舍
///
/// 正常 HTTP 半关闭（客户端 `shutdown(SHUT_WR)` → 服务端回响应）在秒级完成，
/// 远小于该值；设得更长只是让"被钉住的 socket"多占一会儿 fd。要调整改这一个常量。
pub const BRIDGE_HALF_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(300);

/// 读到 EOF（`Ok(0)`）时通知一次的透明包装。
///
/// 仅服务于 [`BRIDGE_HALF_CLOSE_GRACE`] 的计时：让外层能知道"某个方向已经结束"，
/// 而不必自己实现双向拷贝（自己实现会引入 `split` 的锁竞争，影响大流量吞吐）。
/// 读写语义原样转发。
struct EofWatcher<S> {
    inner: S,
    notify: std::sync::Arc<tokio::sync::Notify>,
    seen_eof: bool,
}

impl<S> EofWatcher<S> {
    fn new(inner: S, notify: std::sync::Arc<tokio::sync::Notify>) -> Self {
        Self {
            inner,
            notify,
            seen_eof: false,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for EofWatcher<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r {
            // 本次没读到任何字节 = 对端已 EOF（或读端已关闭）
            if buf.filled().len() == before && !this.seen_eof {
                this.seen_eof = true;
                // notify_one（而非 notify_waiters）：即使此刻还没有 waiter，
                // 也会存下一个许可，后续 notified().await 立即返回，避免丢通知
                this.notify.notify_one();
            }
        }
        r
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for EofWatcher<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// 桥接两个双向流，并返回双向传输的字节数。
///
/// 返回 `(stream1 -> stream2, stream2 -> stream1)`，用于流量统计
/// （调用方在桥接结束后把计数累加进指标）。
///
/// 注意：字节数在桥接过程结束才返回——若桥接被取消（任务 abort）或触发
/// [`BRIDGE_HALF_CLOSE_GRACE`] 强制结束，调用方拿不到计数，这是有意的取舍
/// （避免在热路径上共享原子计数开销）。
pub async fn bridge_streams_counted<S1, S2>(
    stream1: S1,
    stream2: S2,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    bridge_streams_counted_with_grace(stream1, stream2, BRIDGE_HALF_CLOSE_GRACE).await
}

/// [`bridge_streams_counted`] 的实现体；宽限期可注入（供回归测试用）。
async fn bridge_streams_counted_with_grace<S1, S2>(
    stream1: S1,
    stream2: S2,
    grace: std::time::Duration,
) -> Result<(u64, u64), Box<dyn std::error::Error + Send + Sync>>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut s1 = EofWatcher::new(stream1, notify.clone());
    let mut s2 = EofWatcher::new(stream2, notify.clone());

    // Box::pin：让 future 成为单个可 drop 的局部变量，select 之后能立即释放
    // 对 s1/s2 的可变借用（tokio::pin! 的隐藏局部会持有借用到作用域结束）。
    let mut copy_fut = Box::pin(tokio::io::copy_bidirectional(&mut s1, &mut s2));

    let result = tokio::select! {
        r = &mut copy_fut => r,
        _ = async {
            // 1) 等到"某一方向结束"
            notify.notified().await;
            // 2) 再给另一方向一个宽限期；仍不结束说明对端半死 → 强制释放
            tokio::time::sleep(grace).await;
        } => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "bridge half-close grace ({}s) exceeded: one direction finished but the peer \
                 kept the other direction open without FIN; force-closing to release resources",
                grace.as_secs()
            ),
        )),
    };
    drop(copy_fut);

    // 收尾带超时：即使某个 shutdown 被对端拖住，也不能让任务再挂住（否则又变成 fd 泄漏）
    let shutdown_cap = std::time::Duration::from_secs(5);
    let _ = tokio::time::timeout(shutdown_cap, s1.shutdown()).await;
    let _ = tokio::time::timeout(shutdown_cap, s2.shutdown()).await;

    match result {
        Ok((n1, n2)) => {
            log::debug!(
                "Bridge complete: stream1->stream2: {} bytes, stream2->stream1: {} bytes",
                n1,
                n2
            );
            log::info!("Bridge streams closed");
            Ok((n1, n2))
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::TimedOut {
                log::warn!("{}", e);
            }
            Err(e.into())
        }
    }
}

// 导出重试模块
pub mod retry;

/// 速率限制模块
///
/// 提供基于令牌桶算法的带宽限制功能，支持对读写操作进行限速。
pub mod rate_limiter;

/// 本地时区时间格式化模块
///
/// 日志时间戳、日志轮转日期、frps 管理 API 展示时间共用同一份实现，
/// 保证同一时刻在各处的写法一致（不会一处本地时间、一处 UTC）。
pub mod localtime;

/// 日志初始化模块
///
/// 对齐原版 frp `[log]` 段：`to` / `level` / `maxDays`，
/// 支持输出到 stderr + 日志文件（按天轮转、按天数清理）。
pub mod logging;

// 重新导出常用类型
pub use logging::init as init_logging;
pub use rate_limiter::{parse_bandwidth_limit, RateLimitedReader, RateLimitedWriter, TokenBucket};
pub use retry::{
    retry, retry_with_default, ConnectionError, RetryConfig, RetryResult, RetryableError,
};

#[cfg(test)]
mod bridge_stream_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 建立一条本地 TCP 连接，返回 (服务端侧, 客户端侧)
    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn test_bridge_streams_counted_reports_both_directions() {
        let (s1, mut c1) = tcp_pair().await;
        let (s2, mut c2) = tcp_pair().await;

        // 桥接两条连接的服务端侧：c1 <-> s1 <-> bridge <-> s2 <-> c2
        let handle = tokio::spawn(async move { bridge_streams_counted(s1, s2).await });

        c1.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        c2.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");

        c2.write_all(b"world!!").await.unwrap();
        let mut got2 = [0u8; 7];
        c1.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"world!!");

        c1.shutdown().await.unwrap();
        c2.shutdown().await.unwrap();

        let (c1_to_c2, c2_to_c1) = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(c1_to_c2, 5);
        assert_eq!(c2_to_c1, 7);
    }

    /// 复现线上 fd 泄漏形态：后端回完响应后**半关闭**（只关写端），
    /// 而 visitor（扫描器）既不发数据也不关连接。
    /// 期望：宽限期到点后桥接自行结束并释放两侧句柄，而不是永久挂起。
    #[tokio::test]
    async fn test_bridge_half_close_grace_releases_stuck_visitor_socket() {
        let (s1, mut c1) = tcp_pair().await;
        let (s2, mut c2) = tcp_pair().await;
        let handle = tokio::spawn(async move {
            bridge_streams_counted_with_grace(s1, s2, std::time::Duration::from_millis(200)).await
        });

        // 后端（.75）侧半关闭：只关写端 ⇒ 桥接的 stream2 方向读到 EOF；
        // c2 仍可读（TCP 半关闭语义），因此"另一方向写不进去"不会发生，
        // 桥接确实会停在"等 visitor FIN"上 —— 这正是线上卡死的那一步。
        c2.shutdown().await.unwrap();

        let started = std::time::Instant::now();
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("桥接未在半关闭宽限期内结束 ⇒ fd 会永久泄漏（B2 回归）")
            .expect("桥接任务不应 panic");
        assert!(res.is_err(), "半关闭宽限超时应返回错误，实际: {:?}", res);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "不应在宽限期之前就放弃该方向"
        );

        // 桥接结束后 visitor 侧句柄被释放：c1 读到 EOF（0 字节）而非报错挂住
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), c1.read(&mut buf))
            .await
            .expect("visitor 侧应在桥接结束后被关闭")
            .unwrap();
        assert_eq!(n, 0);
    }

    /// 宽限期不得误杀"双向都活着"的连接：本环境有 300s 长请求、50MB 上传、
    /// 长时间无数据的 SSH/WebSocket 会话，它们都不该被回收。
    #[tokio::test]
    async fn test_bridge_grace_does_not_affect_live_connections() {
        let (s1, mut c1) = tcp_pair().await;
        let (s2, mut c2) = tcp_pair().await;
        let handle = tokio::spawn(async move {
            bridge_streams_counted_with_grace(s1, s2, std::time::Duration::from_millis(100)).await
        });

        // 空闲远超宽限期，但两个方向都没 EOF ⇒ 不计时、不许被回收
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        c1.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(2), c2.read_exact(&mut got))
            .await
            .expect("宽限期不应误杀仍然活着的连接（SSH/WebSocket/长请求场景）")
            .unwrap();
        assert_eq!(&got, b"ping");

        c1.shutdown().await.unwrap();
        c2.shutdown().await.unwrap();
        let (n1, n2) = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(n1, 4);
        assert_eq!(n2, 0);
    }

    #[tokio::test]
    async fn test_bridge_streams_delegates_and_forwards() {
        let (s1, mut c1) = tcp_pair().await;
        let (s2, mut c2) = tcp_pair().await;
        let handle = tokio::spawn(async move { bridge_streams(s1, s2).await });

        c1.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c2.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        c1.shutdown().await.unwrap();
        c2.shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
