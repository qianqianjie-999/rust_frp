use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 令牌桶速率限制器
///
/// 以恒定速率生成令牌，每次读写消耗对应令牌。
/// 令牌不足时等待补充。
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// 创建新的令牌桶
    ///
    /// # 参数
    ///
    /// * `rate_bytes_per_sec` - 每秒生成的令牌数（字节）
    pub fn new(rate_bytes_per_sec: f64) -> Self {
        let capacity = rate_bytes_per_sec;
        Self {
            capacity,
            tokens: capacity,
            rate: rate_bytes_per_sec,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }

    fn consume(&mut self, bytes: usize) {
        self.tokens -= bytes as f64;
    }

    fn tokens_available(&self) -> f64 {
        self.tokens
    }
}

/// 解析带宽限制字符串
///
/// 支持格式：
/// - "10MB" → 10 * 1024 * 1024 = 10485760 bytes/sec
/// - "500KB" → 500 * 1024 = 512000 bytes/sec
/// - "1GB" → 1 * 1024 * 1024 * 1024 = 1073741824 bytes/sec
pub fn parse_bandwidth_limit(s: &str) -> Option<f64> {
    let s = s.trim().to_uppercase();
    if s.is_empty() {
        return None;
    }

    let (num_part, unit) = if s.ends_with("GB") {
        let n = s[..s.len() - 2].trim();
        (n, 1024.0 * 1024.0 * 1024.0)
    } else if s.ends_with("MB") {
        let n = s[..s.len() - 2].trim();
        (n, 1024.0 * 1024.0)
    } else if s.ends_with("KB") {
        let n = s[..s.len() - 2].trim();
        (n, 1024.0)
    } else if s.ends_with('B') {
        let n = s[..s.len() - 1].trim();
        (n, 1.0)
    } else {
        (s.as_str(), 1.0)
    };

    num_part.parse::<f64>().ok().map(|n| n * unit)
}

/// 限速读取器
pub struct RateLimitedReader<R> {
    inner: R,
    bucket: TokenBucket,
    min_bytes: usize,
}

impl<R: AsyncRead + Unpin> RateLimitedReader<R> {
    /// 创建新的限速读取器
    ///
    /// # 参数
    ///
    /// * `inner` - 内部读取器
    /// * `rate_bytes_per_sec` - 每秒允许读取的最大字节数
    pub fn new(inner: R, rate_bytes_per_sec: f64) -> Self {
        Self {
            inner,
            bucket: TokenBucket::new(rate_bytes_per_sec),
            min_bytes: 4096,
        }
    }

    /// 设置单次读取的最小字节数
    ///
    /// # 参数
    ///
    /// * `min_bytes` - 最小读取字节数
    pub fn with_min_bytes(mut self, min_bytes: usize) -> Self {
        self.min_bytes = min_bytes;
        self
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RateLimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.bucket.refill();
        let available = self.bucket.tokens_available();
        if available <= 0.0 {
            let delay = Duration::from_secs_f64((-available) / self.bucket.rate + 0.001);
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                waker.wake();
            });
            return Poll::Pending;
        }

        let remaining = buf.remaining();
        let max_bytes = (available as usize).min(remaining);
        let limit = max_bytes.max(self.min_bytes);
        let actual_limit = limit.min(remaining);

        let unfilled = buf.initialize_unfilled();
        let inner_buf_slice = &mut unfilled[..actual_limit];
        let mut limited_buf = ReadBuf::new(inner_buf_slice);

        let filled_before = limited_buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, &mut limited_buf);
        match result {
            Poll::Ready(Ok(())) => {
                let filled = limited_buf.filled().len() - filled_before;
                self.bucket.consume(filled);
                buf.advance(filled);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// 限速写入器
pub struct RateLimitedWriter<W> {
    inner: W,
    bucket: TokenBucket,
    min_bytes: usize,
}

impl<W: AsyncWrite + Unpin> RateLimitedWriter<W> {
    /// 创建新的限速写入器
    ///
    /// # 参数
    ///
    /// * `inner` - 内部写入器
    /// * `rate_bytes_per_sec` - 每秒允许写入的最大字节数
    pub fn new(inner: W, rate_bytes_per_sec: f64) -> Self {
        Self {
            inner,
            bucket: TokenBucket::new(rate_bytes_per_sec),
            min_bytes: 4096,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for RateLimitedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.bucket.refill();
        let available = self.bucket.tokens_available();
        if available <= 0.0 {
            let delay = Duration::from_secs_f64((-available) / self.bucket.rate + 0.001);
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                waker.wake();
            });
            return Poll::Pending;
        }

        let max_write = (available as usize).max(self.min_bytes);
        let write_limit = max_write.min(buf.len());
        let result = Pin::new(&mut self.inner).poll_write(cx, &buf[..write_limit]);
        match result {
            Poll::Ready(Ok(n)) => {
                self.bucket.consume(n);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth_limit() {
        assert_eq!(parse_bandwidth_limit("10MB"), Some(10.0 * 1024.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("1GB"), Some(1024.0 * 1024.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("500KB"), Some(500.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("100"), Some(100.0));
        assert_eq!(parse_bandwidth_limit(""), None);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1024.0);
        assert!(bucket.tokens_available() > 0.0);
        bucket.consume(512);
        bucket.refill();
        assert!(bucket.tokens_available() > 0.0);
    }
}