use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 令牌桶速率限制器
///
/// 以恒定速率生成令牌，每次读写消耗对应令牌。
/// 令牌不足时等待补充。
///
/// # 安全性说明
///
/// 构造时会强制把速率规整为「有限且为正」的值：任何 NaN / 无穷 / 非正值
/// 都会被降级为 1 字节/秒。这一点非常关键——历史实现里 `(-available) / rate`
/// 在 `rate == 0` 时会产生 NaN，进而让 `Duration::from_secs_f64` panic，
/// 直接把转发任务打挂。
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last_refill: Instant,
}

/// 令牌桶的最小可用速率（字节/秒），用于兜底非法配置
const MIN_RATE_BYTES_PER_SEC: f64 = 1.0;

impl TokenBucket {
    /// 创建新的令牌桶
    ///
    /// # 参数
    ///
    /// * `rate_bytes_per_sec` - 每秒生成的令牌数（字节）。
    ///   非有限值或非正值会被规整为 [`MIN_RATE_BYTES_PER_SEC`]，永不 panic。
    pub fn new(rate_bytes_per_sec: f64) -> Self {
        let rate = sanitize_rate(rate_bytes_per_sec);
        Self {
            capacity: rate,
            tokens: rate,
            rate,
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

    /// 计算补足 1 个字节所需要等待的时间
    ///
    /// 保证返回值一定是合法、有限、且严格大于 0 的 [`Duration`]，
    /// 不会出现 NaN 导致的 panic。
    fn time_until_available(&self) -> Duration {
        const FALLBACK: Duration = Duration::from_millis(1);

        let deficit = (1.0 - self.tokens).max(0.0);
        let secs = deficit / self.rate;
        if !secs.is_finite() || secs < 0.0 {
            return FALLBACK;
        }
        // 再加 1ms 余量，避免浮点误差造成「醒来仍然没令牌」的忙轮询
        Duration::try_from_secs_f64(secs)
            .map(|d| d + FALLBACK)
            .unwrap_or(FALLBACK)
    }
}

/// 把速率规整为有限正值，非法输入统一降级为最小值
fn sanitize_rate(rate: f64) -> f64 {
    if rate.is_finite() && rate >= MIN_RATE_BYTES_PER_SEC {
        rate
    } else {
        MIN_RATE_BYTES_PER_SEC
    }
}

/// 解析带宽限制字符串
///
/// 支持格式：
/// - "10MB" → 10 * 1024 * 1024 = 10485760 bytes/sec
/// - "500KB" → 500 * 1024 = 512000 bytes/sec
/// - "1GB" → 1 * 1024 * 1024 * 1024 = 1073741824 bytes/sec
///
/// # 返回值
///
/// - 合法且为正的带宽 → `Some(bytes_per_sec)`
/// - 空串、非法格式、非数字、非正值（如 `"0"`、`"-1"`）、NaN/无穷 → `None`
///
/// 调用方拿到 `None` 时应视为「未配置限速」，同时建议在配置校验阶段
/// 就把非法值直接报错，避免出现「配了限速但静默不生效」的错觉。
pub fn parse_bandwidth_limit(s: &str) -> Option<f64> {
    let s = s.trim().to_uppercase();
    if s.is_empty() {
        return None;
    }

    let (num_part, unit) = if let Some(n) = s.strip_suffix("GB") {
        (n.trim(), 1024.0 * 1024.0 * 1024.0)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n.trim(), 1024.0 * 1024.0)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n.trim(), 1024.0)
    } else if let Some(n) = s.strip_suffix('B') {
        (n.trim(), 1.0)
    } else {
        (s.as_str(), 1.0)
    };

    num_part
        .parse::<f64>()
        .ok()
        .map(|n| n * unit)
        .filter(|v| v.is_finite() && *v > 0.0)
}

/// 限速读取器
pub struct RateLimitedReader<R> {
    inner: R,
    bucket: TokenBucket,
    min_bytes: usize,
    /// 令牌不足时挂起的定时器；用状态机驱动，不再在每个 poll 里 spawn 任务
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
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
            sleep: None,
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
        loop {
            // 1. 若已有挂起的定时器，先驱动它；未就绪直接返回 Pending，
            //    由同一个 waker 唤醒，不再新起任务。
            if self.sleep.is_some() {
                let ready = match self.sleep.as_mut() {
                    Some(sleep) => sleep.as_mut().poll(cx).is_ready(),
                    None => true,
                };
                if ready {
                    self.sleep = None;
                } else {
                    return Poll::Pending;
                }
            }

            // 2. 补充令牌并判断是否有额度
            self.bucket.refill();
            let available = self.bucket.tokens_available();
            if available <= 0.0 {
                let delay = self.bucket.time_until_available();
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                continue;
            }

            // 3. 有额度，按剩余额度限制本次读取
            let remaining = buf.remaining();
            let max_bytes = (available as usize).min(remaining);
            let limit = max_bytes.max(self.min_bytes);
            let actual_limit = limit.min(remaining);

            let unfilled = buf.initialize_unfilled();
            let inner_buf_slice = &mut unfilled[..actual_limit];
            let mut limited_buf = ReadBuf::new(inner_buf_slice);

            let filled_before = limited_buf.filled().len();
            let result = Pin::new(&mut self.inner).poll_read(cx, &mut limited_buf);
            return match result {
                Poll::Ready(Ok(())) => {
                    let filled = limited_buf.filled().len() - filled_before;
                    self.bucket.consume(filled);
                    buf.advance(filled);
                    Poll::Ready(Ok(()))
                }
                other => other,
            };
        }
    }
}

/// 限速写入器
pub struct RateLimitedWriter<W> {
    inner: W,
    bucket: TokenBucket,
    min_bytes: usize,
    /// 同 [`RateLimitedReader::sleep`]
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
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
            sleep: None,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for RateLimitedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        loop {
            if self.sleep.is_some() {
                let ready = match self.sleep.as_mut() {
                    Some(sleep) => sleep.as_mut().poll(cx).is_ready(),
                    None => true,
                };
                if ready {
                    self.sleep = None;
                } else {
                    return Poll::Pending;
                }
            }

            self.bucket.refill();
            let available = self.bucket.tokens_available();
            if available <= 0.0 {
                let delay = self.bucket.time_until_available();
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                continue;
            }

            let max_write = (available as usize).max(self.min_bytes);
            let write_limit = max_write.min(buf.len());
            return match Pin::new(&mut self.inner).poll_write(cx, &buf[..write_limit]) {
                Poll::Ready(Ok(n)) => {
                    self.bucket.consume(n);
                    Poll::Ready(Ok(n))
                }
                other => other,
            };
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
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_parse_bandwidth_limit() {
        assert_eq!(parse_bandwidth_limit("10MB"), Some(10.0 * 1024.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("1GB"), Some(1024.0 * 1024.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("500KB"), Some(500.0 * 1024.0));
        assert_eq!(parse_bandwidth_limit("100"), Some(100.0));
        assert_eq!(
            parse_bandwidth_limit("  2 mb "),
            Some(2.0 * 1024.0 * 1024.0)
        );
        assert_eq!(parse_bandwidth_limit(""), None);
    }

    #[test]
    fn test_parse_bandwidth_limit_rejects_invalid() {
        // 非正值 / 非法格式必须被拒绝，而不是静默当作 0 速率
        assert_eq!(parse_bandwidth_limit("0"), None);
        assert_eq!(parse_bandwidth_limit("0MB"), None);
        assert_eq!(parse_bandwidth_limit("-1KB"), None);
        assert_eq!(parse_bandwidth_limit("abc"), None);
        assert_eq!(parse_bandwidth_limit("NaN"), None);
        assert_eq!(parse_bandwidth_limit("inf"), None);
    }

    #[test]
    fn test_token_bucket_sanitizes_rate() {
        // 0 / 负数 / NaN / 无穷都不得产生非法内部状态
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let bucket = TokenBucket::new(bad);
            assert!(bucket.rate.is_finite() && bucket.rate > 0.0);
            // 等待时间必须永远是可用的 Duration
            let d = bucket.time_until_available();
            assert!(d > Duration::ZERO);
        }
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1024.0);
        assert!(bucket.tokens_available() > 0.0);
        bucket.consume(512);
        bucket.refill();
        assert!(bucket.tokens_available() > 0.0);
    }

    /// 回归测试：历史实现在 bandwidth_limit = "0" 时 panic
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_zero_bandwidth_does_not_panic() {
        let mut reader = RateLimitedReader::new(std::io::Cursor::new(vec![0u8; 65536]), 0.0);
        let mut out = [0u8; 1024];
        // 只要不 panic 即通过（可能超时，超时也被容忍）
        let _ = tokio::time::timeout(Duration::from_millis(300), reader.read(&mut out)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_negative_bandwidth_does_not_panic() {
        let mut writer = RateLimitedWriter::new(Vec::new(), -5.0);
        let _ = tokio::time::timeout(Duration::from_millis(300), writer.write(&[0u8; 64])).await;
    }

    /// 正常速率下应能读到数据，验证状态机没有把流程卡死
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_rate_limited_reader_reads_data() {
        let payload = vec![7u8; 8192];
        let mut reader =
            RateLimitedReader::new(std::io::Cursor::new(payload.clone()), 1024.0 * 1024.0)
                .with_min_bytes(1024);
        let mut out = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read(&mut out))
            .await
            .expect("read should not hang")
            .expect("read should succeed");
        assert!(n > 0);
        assert_eq!(&out[..n], &payload[..n]);
    }
}
