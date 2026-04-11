use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// 重试机制
pub async fn retry<F, T, E>(
    mut f: F,
    max_attempts: usize,
    delay: Duration,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Display,
{
    let mut last_err: Option<E> = None;
    for attempt in 0..max_attempts {
        match f() {
            Ok(t) => return Ok(t),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts - 1 {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    Err(last_err.unwrap())
}
