use std::time::Duration;
use std::future::Future;
use log::{info, warn, error};

/// 重试策略配置
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// 最大重试次数
    pub max_retries: u32,
    /// 初始重试间隔
    pub initial_delay: Duration,
    /// 最大重试间隔
    pub max_delay: Duration,
    /// 退避倍数
    pub backoff_multiplier: f64,
    /// 是否使用指数退避
    pub use_exponential_backoff: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            use_exponential_backoff: true,
        }
    }
}

impl RetryConfig {
    /// 创建快速重试配置
    pub fn fast() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 1.5,
            use_exponential_backoff: true,
        }
    }

    /// 创建慢速重试配置
    pub fn slow() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            use_exponential_backoff: true,
        }
    }

    /// 计算第 n 次重试的延迟
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_secs(0);
        }

        let delay = if self.use_exponential_backoff {
            let multiplier = self.backoff_multiplier.powi(attempt as i32 - 1);
            let delay_ms = (self.initial_delay.as_millis() as f64 * multiplier) as u64;
            Duration::from_millis(delay_ms)
        } else {
            self.initial_delay * attempt
        };

        delay.min(self.max_delay)
    }
}

/// 可重试的错误 trait
pub trait RetryableError: std::error::Error {
    /// 判断错误是否可重试
    fn is_retryable(&self) -> bool;
}

/// 重试结果
#[derive(Debug)]
pub struct RetryResult<T> {
    pub value: T,
    pub attempts: u32,
    pub total_delay: Duration,
}

/// 执行带重试的操作
pub async fn retry<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    operation: F,
) -> Result<RetryResult<T>, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error = None;
    let mut total_delay = Duration::from_secs(0);

    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(value) => {
                if attempt > 0 {
                    info!("{} succeeded after {} attempts", operation_name, attempt + 1);
                }
                return Ok(RetryResult {
                    value,
                    attempts: attempt + 1,
                    total_delay,
                });
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                last_error = Some(e);

                if attempt < config.max_retries {
                    let delay = config.calculate_delay(attempt + 1);
                    total_delay += delay;
                    
                    warn!(
                        "{} failed (attempt {}/{}): {}. Retrying in {:?}...",
                        operation_name,
                        attempt + 1,
                        config.max_retries + 1,
                        error_msg,
                        delay
                    );
                    
                    tokio::time::sleep(delay).await;
                } else {
                    error!(
                        "{} failed after {} attempts: {}",
                        operation_name,
                        attempt + 1,
                        error_msg
                    );
                }
            }
        }
    }

    Err(last_error.unwrap())
}

/// 执行带重试的操作，使用默认配置
pub async fn retry_with_default<F, Fut, T, E>(
    operation_name: &str,
    operation: F,
) -> Result<RetryResult<T>, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    retry(&RetryConfig::default(), operation_name, operation).await
}

/// 连接错误类型
#[derive(Debug)]
pub enum ConnectionError {
    Io(std::io::Error),
    Timeout,
    Refused,
    Reset,
    Other(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Io(e) => write!(f, "IO error: {}", e),
            ConnectionError::Timeout => write!(f, "Connection timeout"),
            ConnectionError::Refused => write!(f, "Connection refused"),
            ConnectionError::Reset => write!(f, "Connection reset"),
            ConnectionError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectionError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl RetryableError for ConnectionError {
    fn is_retryable(&self) -> bool {
        match self {
            ConnectionError::Timeout => true,
            ConnectionError::Refused => true,
            ConnectionError::Reset => true,
            ConnectionError::Io(e) => {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::NotConnected
                )
            }
            ConnectionError::Other(_) => false,
        }
    }
}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::ConnectionRefused => ConnectionError::Refused,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                ConnectionError::Reset
            }
            std::io::ErrorKind::TimedOut => ConnectionError::Timeout,
            _ => ConnectionError::Io(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_calculate_delay() {
        let config = RetryConfig::default();
        
        // 第一次重试
        let delay1 = config.calculate_delay(1);
        assert_eq!(delay1, Duration::from_millis(100));
        
        // 第二次重试（指数退避）
        let delay2 = config.calculate_delay(2);
        assert_eq!(delay2, Duration::from_millis(200));
        
        // 第三次重试
        let delay3 = config.calculate_delay(3);
        assert_eq!(delay3, Duration::from_millis(400));
    }

    #[test]
    fn test_calculate_delay_max_cap() {
        let config = RetryConfig {
            max_retries: 10,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 10.0,
            use_exponential_backoff: true,
        };
        
        // 延迟应该被限制在 max_delay
        let delay = config.calculate_delay(5);
        assert_eq!(delay, Duration::from_secs(5));
    }
}
