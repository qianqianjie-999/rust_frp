//! FRP 工具函数模块
//!
//! 该模块提供了 FRP 项目中常用的工具函数，包括：
//!
//! ## 主要功能
//!
//! 1. **时间戳获取**
//!    - `get_timestamp()`: 获取当前 Unix 时间戳（秒）
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
        .unwrap()
        .as_secs() as i64
}

/// 解析地址字符串为 SocketAddr
pub fn parse_addr(addr: &str) -> Result<SocketAddr, std::io::Error> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid address"))
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
    mut stream1: S1,
    mut stream2: S2,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let result = tokio::io::copy_bidirectional(&mut stream1, &mut stream2).await;

    let _ = stream1.shutdown().await;
    let _ = stream2.shutdown().await;

    match result {
        Ok((n1, n2)) => {
            log::debug!(
                "Bridge complete: stream1->stream2: {} bytes, stream2->stream1: {} bytes",
                n1,
                n2
            );
            log::info!("Bridge streams closed");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

// 导出重试模块
pub mod retry;

/// 速率限制模块
///
/// 提供基于令牌桶算法的带宽限制功能，支持对读写操作进行限速。
pub mod rate_limiter;

// 重新导出常用类型
pub use rate_limiter::{parse_bandwidth_limit, RateLimitedReader, RateLimitedWriter, TokenBucket};
pub use retry::{
    retry, retry_with_default, ConnectionError, RetryConfig, RetryResult, RetryableError,
};
