//! 应用层压缩（use_compression）：snappy 工作连接压缩流
//!
//! 语义对齐 frp 原版的 per-proxy `use_compression`（原版同样使用 snappy）：
//! 握手消息（NewWorkConn / StartWorkConn）始终明文且不压缩，握手完成后
//! 两端各自把工作连接字节流包装为本结构，之后全部流量按块压缩。
//!
//! # 帧格式
//!
//! ```text
//! [4B 大端压缩载荷长度][snappy raw block 载荷]
//! ```
//!
//! - 使用 snappy **raw block** 格式（无额外帧头），与 Go 版 `snappy.Encode`
//!   同属一类块压缩；块间无依赖，单块损坏即视为协议错误立即断连；
//! - 单条记录明文上限 [`MAX_BLOCK`]（32KB），超限分块；
//! - 载荷长度上限 [`MAX_FRAME_PAYLOAD`]：`snap::raw::max_compress_len(MAX_BLOCK)`，
//!   超限视为协议攻击立即断连（fail-closed）。
//!
//! # 与加密的叠加顺序
//!
//! 两端一致地「先压缩、后加密」（加密包装在压缩之外）：先压缩明文再加密，
//! 既避免密文不可压缩导致压缩失效，也保证两条链路语义正交。
//!
//! # 性能说明
//!
//! snappy 侧重吞吐（对压缩率不敏感），适合隧道场景。已压缩数据
//! （如视频流）收益有限但开销同样很小；若带宽敏感且流量已压缩，
//! 建议关闭 `use_compression`。

use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// 单块压缩的明文上限（32KB）
pub const MAX_BLOCK: usize = 32 * 1024;

const HEADER_LEN: usize = 4;

/// 单帧压缩载荷上限（snappy 最坏膨胀上界）
fn max_frame_payload() -> usize {
    snap::raw::max_compress_len(MAX_BLOCK)
}

/// snappy 压缩流包装器
///
/// 包装任意 [`FrpConn`](crate::FrpConn)，自身同样实现
/// `AsyncRead + AsyncWrite + FrpConn`，可与 [`crate::crypto::EncryptedStream`]
/// 叠加（压缩在内、加密在外）并参与 `bridge_streams` 桥接。
pub struct CompressedStream<S> {
    inner: S,
    /// 待发送的压缩字节（完整帧或半帧），`out_pos` 为已写出偏移
    out_buf: Vec<u8>,
    out_pos: usize,
    /// 读侧累积缓冲（未凑齐一帧）
    rx_buf: Vec<u8>,
    /// 已解压待读明文，`in_pos` 为已消费偏移
    in_plain: Vec<u8>,
    in_pos: usize,
    /// 粘性错误：帧损坏后连接不可恢复，后续轮询持续返回该错误
    sticky_err: Option<std::io::Error>,
}

impl<S: crate::FrpConn> CompressedStream<S> {
    /// 创建压缩流
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            out_buf: Vec::new(),
            out_pos: 0,
            rx_buf: Vec::new(),
            in_plain: Vec::new(),
            in_pos: 0,
            sticky_err: None,
        }
    }

    /// 把一块明文压缩并追加为一帧到 `out_buf`
    fn compress_into_out_buf(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        let compressed = snap::raw::Encoder::new()
            .compress_vec(chunk)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        self.out_buf
            .extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        self.out_buf.extend_from_slice(&compressed);
        Ok(())
    }

    /// 尝试把 `out_buf` 中剩余字节写到底层
    fn try_drain_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.out_pos < self.out_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out_buf[self.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "compressed stream: underlying wrote 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => {
                    self.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out_buf.clear();
        self.out_pos = 0;
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    /// 尝试从 `rx_buf` 解析并解压一帧；成功后明文追加到 `in_plain`
    fn try_decompress_frame(&mut self) -> std::io::Result<bool> {
        if self.rx_buf.len() < HEADER_LEN {
            return Ok(false);
        }
        let payload_len =
            u32::from_be_bytes(self.rx_buf[..HEADER_LEN].try_into().expect("header len")) as usize;
        if payload_len == 0 || payload_len > max_frame_payload() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("compressed frame length {} out of range", payload_len),
            ));
        }
        let frame_len = HEADER_LEN + payload_len;
        if self.rx_buf.len() < frame_len {
            return Ok(false);
        }
        let payload = &self.rx_buf[HEADER_LEN..frame_len];
        let plain = snap::raw::Decoder::new()
            .decompress_vec(payload)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("snappy decompress failed: {e}"),
                )
            })?;
        if plain.len() > MAX_BLOCK {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompressed block of {} bytes exceeds limit", plain.len()),
            ));
        }
        self.in_plain.extend_from_slice(&plain);
        self.rx_buf.drain(..frame_len);
        Ok(true)
    }
}

impl<S: crate::FrpConn> AsyncRead for CompressedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if let Some(e) = &this.sticky_err {
            return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
        }

        // 已有解压明文 → 直接拷出
        if this.in_pos < this.in_plain.len() {
            let n = std::cmp::min(buf.remaining(), this.in_plain.len() - this.in_pos);
            buf.put_slice(&this.in_plain[this.in_pos..this.in_pos + n]);
            this.in_pos += n;
            if this.in_pos == this.in_plain.len() {
                this.in_plain.clear();
                this.in_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            // 先尝试解析已有缓冲（上次可能已凑齐完整帧）
            match this.try_decompress_frame() {
                Ok(true) => {
                    let n = std::cmp::min(buf.remaining(), this.in_plain.len());
                    buf.put_slice(&this.in_plain[..n]);
                    this.in_pos = n;
                    if this.in_pos == this.in_plain.len() {
                        this.in_plain.clear();
                        this.in_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(false) => {} // 帧未凑齐，继续读底层
                Err(e) => {
                    this.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(e));
                }
            }

            // 从底层读原始字节
            let mut tmp = [0u8; 4096];
            let mut read_buf = tokio::io::ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    // 底层 EOF：缓冲耗尽即正常结束；仍有半帧说明流被截断
                    if this.rx_buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let e = std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "compressed stream: EOF mid-frame",
                    );
                    this.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    this.rx_buf.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => {
                    this.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                    return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: crate::FrpConn> AsyncWrite for CompressedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if let Some(e) = &this.sticky_err {
            return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
        }
        // 先排空旧缓冲；不 Ready 则在消费新数据前返回 Pending（数据不丢失）
        ready!(this.try_drain_out(cx))?;

        // 超过单块上限时分块落多帧（write_all 会把整段传进来，需在此分块）
        for chunk in buf.chunks(MAX_BLOCK) {
            if let Err(e) = this.compress_into_out_buf(chunk) {
                this.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                return Poll::Ready(Err(e));
            }
        }
        let _ = this.try_drain_out(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(e) = &this.sticky_err {
            return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
        }
        this.try_drain_out(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 先把发送缓冲全部排空（含最后一帧），再关闭底层连接
        ready!(Self::poll_flush(Pin::new(&mut *this), cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: crate::FrpConn> crate::FrpConn for CompressedStream<S> {
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.remote_addr()
    }
}

#[cfg(test)]
mod compress_tests {
    use super::*;
    use crate::FrpConn;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 测试用 FrpConn 适配器（包一层内存双工流）
    struct TestConn(tokio::io::DuplexStream);

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl FrpConn for TestConn {
        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    /// 内存双工管道（借用 tokio duplex 模拟底层流）
    fn duplex() -> (TestConn, TestConn) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        (TestConn(a), TestConn(b))
    }

    #[tokio::test]
    async fn test_roundtrip_small_and_repetitive() {
        // 重复数据应被压缩（帧载荷明显小于明文）
        let (a, b) = duplex();
        let mut sender = CompressedStream::new(a);
        let mut receiver = CompressedStream::new(b);

        let payload = b"hello frp compression ".repeat(100);
        sender.write_all(&payload).await.unwrap();
        sender.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        receiver.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn test_roundtrip_cross_block_boundary() {
        // 跨块写：超过 MAX_BLOCK 的数据分多帧，读侧按序还原
        let (a, b) = duplex();
        let mut sender = CompressedStream::new(a);
        let mut receiver = CompressedStream::new(b);

        let payload: Vec<u8> = (0..(MAX_BLOCK * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let len = payload.len();
        let (s, r) = tokio::join!(
            async move {
                sender.write_all(&payload).await.unwrap();
                sender.shutdown().await.unwrap();
            },
            async move {
                let mut got = Vec::new();
                receiver.read_to_end(&mut got).await.unwrap();
                got
            }
        );
        assert_eq!(s, ());
        assert_eq!(r.len(), len);
    }

    #[tokio::test]
    async fn test_compression_inside_encryption_roundtrip() {
        // 与工作连接实际包装顺序一致：压缩在内、加密在外
        let (a, b) = duplex();
        let key = vec![7u8; 32];
        let mut sender =
            crate::crypto::EncryptedStream::new(CompressedStream::new(a), &key).unwrap();
        let mut receiver =
            crate::crypto::EncryptedStream::new(CompressedStream::new(b), &key).unwrap();

        let payload = b"frp stacked compression+encryption ".repeat(200);
        let expected_len = payload.len();
        sender.write_all(&payload).await.unwrap();
        sender.flush().await.unwrap();

        let mut got = vec![0u8; expected_len];
        receiver.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn test_corrupted_frame_rejected() {
        // 直接把随机字节当作压缩载荷写底层：解压失败必须 fail-closed
        let (mut raw_tx, raw_rx) = duplex();
        let mut receiver = CompressedStream::new(raw_rx);

        // 帧头声明 8 字节载荷，内容不是合法 snappy 块
        let mut frame = Vec::new();
        frame.extend_from_slice(&8u32.to_be_bytes());
        frame.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08");
        raw_tx.write_all(&frame).await.unwrap();

        let mut got = [0u8; 16];
        let err = receiver.read(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_truncated_stream_is_eof_error() {
        let (mut raw_tx, raw_rx) = duplex();
        let mut receiver = CompressedStream::new(raw_rx);
        // 只写 2 字节帧头 —— 不足 4 字节头，随后关闭 → EOF mid-frame
        raw_tx.write_all(&[0u8, 0u8]).await.unwrap();
        drop(raw_tx);

        let mut got = [0u8; 8];
        let err = receiver.read(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_oversized_frame_header_rejected() {
        let (mut raw_tx, raw_rx) = duplex();
        let mut receiver = CompressedStream::new(raw_rx);
        // 声明超过膨胀上界的载荷长度 → 立即拒绝
        raw_tx.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();

        let mut got = [0u8; 8];
        let err = receiver.read(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
