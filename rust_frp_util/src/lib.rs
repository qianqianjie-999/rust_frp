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

// 导出重试模块
pub mod retry;

// 重新导出常用类型
pub use retry::{RetryConfig, RetryResult, retry, retry_with_default, ConnectionError, RetryableError};
