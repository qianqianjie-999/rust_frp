use std::time::{SystemTime, UNIX_EPOCH};
use std::net::{SocketAddr, ToSocketAddrs};

/// 获取当前时间戳（秒）
pub fn get_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 解析地址字符串为 SocketAddr
pub fn parse_addr(addr: &str) -> Result<SocketAddr, std::io::Error> {
    addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid address",
        )
    })
}

/// 生成随机 ID
pub fn rand_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    (0..len)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// 桥接两个 TCP 连接，实现双向数据转发
pub async fn bridge_connections(
    conn1: tokio::net::TcpStream,
    conn2: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    bridge_streams(conn1, conn2).await
}

/// 桥接任意两个双向流，实现双向数据转发
/// 支持 TcpStream、TLS stream 等任何实现 AsyncRead + AsyncWrite 的类型
pub async fn bridge_streams<S1, S2>(
    mut stream1: S1,
    mut stream2: S2,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 使用 tokio::io::copy_bidirectional，它会在两个方向上同时复制数据
    // 并且不会在一个方向完成时取消另一个方向的复制，防止数据丢失
    let (n1, n2) = tokio::io::copy_bidirectional(&mut stream1, &mut stream2).await?;
    
    log::debug!("Bridge complete: stream1->stream2: {} bytes, stream2->stream1: {} bytes", n1, n2);
    log::info!("Bridge streams closed");
    Ok(())
}

// 导出重试模块
pub mod retry;

// 重新导出常用类型
pub use retry::{RetryConfig, RetryResult, retry, retry_with_default, ConnectionError, RetryableError};
