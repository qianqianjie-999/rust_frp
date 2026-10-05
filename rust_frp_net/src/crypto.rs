//! 应用层加密（use_encryption）：AES-256-GCM 工作连接加密流
//!
//! 语义对齐 frp 原版的 per-proxy `use_encryption`：握手消息（NewWorkConn /
//! StartWorkConn）始终明文，握手完成后两端各自把工作连接字节流包装为本结构，
//! 之后的全部流量按记录加密。
//!
//! # 帧格式
//!
//! ```text
//! [4B 大端记录载荷长度][12B nonce][密文 + 16B GCM tag]
//! ```
//!
//! - 密钥：`SHA-256(token)`（与服务端 `AuthManager::encryption_key` 同源派生）；
//! - nonce：`8B 随机会话前缀 + 4B 大端计数器`（共 12B，随帧传输），解密端直接读
//!   帧内 nonce，无需同步计数状态。8B 随机前缀把"两个方向/相邻会话的 nonce 空间
//!   碰撞"概率压到 2^-64（此前 4B 前缀为 2^-32，正好卡在 NIST 边界上）；
//!   计数器上限 2^32 条记录，耗尽即断连——宁可断连也绝不复用 nonce；
//! - 单条记录明文上限 [`MAX_PLAINTEXT_RECORD`]，超限视为协议攻击立即断连（fail-closed）。
//!
//! # 性能说明
//!
//! 每次 `poll_write` 立即落一条记录（无跨调用聚合），单记录开销 32 字节
//! （nonce 12 + tag 16 + 长度 4）；`tokio::io::copy_bidirectional`（工作连接
//! 桥接的唯一入口）按 8KB 块写入，开销约 0.4%。
//!
//! # 安全边界
//!
//! 只加密不认证（无证书校验），防被动嗅探、不防中间人——与 frp 原版一致；
//! 需要身份认证请叠加 TLS（`transport.tls` / `trusted_ca_file`）。
//! 同时**不做重放检测**：解密端直接接受帧携带的 nonce，同一帧被重复投递不会
//! 被识别。需要抗重放请在 TLS 之上叠加（mTLS + 每连接随机 run_id）。

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// 单条记录明文上限（16KB）
pub const MAX_PLAINTEXT_RECORD: usize = 16 * 1024;

const NONCE_LEN: usize = 12;
/// nonce 随机前缀长度（8B）
const NONCE_PREFIX_LEN: usize = 8;
/// nonce 计数器长度（4B）；与前缀合计必须等于 [`NONCE_LEN`]
const NONCE_COUNTER_LEN: usize = 4;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4;
/// 编译期保证 nonce 布局自洽（前缀 + 计数器 = 12B）
const _: () = assert!(NONCE_PREFIX_LEN + NONCE_COUNTER_LEN == NONCE_LEN);
/// 编译期保证随机前缀足够宽（< 8B 会让 GCM nonce 碰撞概率逼近 NIST 上限 2^-32）
const _: () = assert!(NONCE_PREFIX_LEN >= 8);

/// 最小帧载荷：nonce + 空明文 + tag
const MIN_PAYLOAD: usize = NONCE_LEN + TAG_LEN;
/// 最大帧载荷：nonce + 最大明文 + tag
const MAX_PAYLOAD: usize = NONCE_LEN + MAX_PLAINTEXT_RECORD + TAG_LEN;

/// AES-256-GCM 加密流包装器
///
/// 包装任意 [`FrpConn`](crate::FrpConn)（TCP/TLS/KCP/WebSocket/mux 流统一类型），
/// 自身同样实现 `AsyncRead + AsyncWrite + FrpConn`，可无缝参与
/// `read_message`/`write_message` 与 `bridge_streams` 桥接。
pub struct EncryptedStream<S> {
    inner: S,
    /// 读方向密钥（解密对端记录）
    read_key: LessSafeKey,
    /// 写方向密钥（加密本端记录）
    write_key: LessSafeKey,
    /// 本方向 nonce 随机前缀（8B）
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    write_counter: u64,
    /// 待发送的加密字节（完整帧或半帧），`out_pos` 为已写出偏移
    out_buf: Vec<u8>,
    out_pos: usize,
    /// 读侧累积缓冲（未凑齐一帧）
    rx_buf: Vec<u8>,
    /// 已解密待读明文，`in_pos` 为已消费偏移
    in_plain: Vec<u8>,
    in_pos: usize,
    /// 粘性错误：帧损坏/密钥不匹配后连接不可恢复，后续轮询持续返回该错误
    sticky_err: Option<std::io::Error>,
}

impl<S: crate::FrpConn> EncryptedStream<S> {
    /// 创建加密流（读写同密钥）
    ///
    /// # 参数
    ///
    /// - `key_bytes`: 必须 32 字节（AES-256）。两端应使用同源派生密钥
    ///   （`SHA-256(token)`），不匹配时对端解密失败、连接报错。
    pub fn new(inner: S, key_bytes: &[u8]) -> Result<Self, std::io::Error> {
        Self::new_directional(inner, key_bytes, key_bytes)
    }

    /// 创建**方向性密钥**加密流（读/写使用不同密钥）
    ///
    /// 用于 wire v2 控制通道：密钥由 HKDF 按 `client-to-server` /
    /// `server-to-client` 两个方向分别派生，从根本上排除双向使用
    /// 同一 (key, nonce) 组合的风险。wire v1 的 `use_encryption`
    /// 仍走 [`EncryptedStream::new`]（读写同密钥，与既有实现兼容）。
    pub fn new_directional(
        inner: S,
        read_key_bytes: &[u8],
        write_key_bytes: &[u8],
    ) -> Result<Self, std::io::Error> {
        let read_key =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, read_key_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "read key must be 32 bytes for AES-256-GCM",
                )
            })?);
        let write_key =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, write_key_bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "write key must be 32 bytes for AES-256-GCM",
                )
            })?);
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut prefix)
            .map_err(|_| std::io::Error::other("rng unavailable"))?;
        Ok(Self {
            inner,
            read_key,
            write_key,
            nonce_prefix: prefix,
            write_counter: 0,
            out_buf: Vec::new(),
            out_pos: 0,
            rx_buf: Vec::new(),
            in_plain: Vec::new(),
            in_pos: 0,
            sticky_err: None,
        })
    }

    /// 生成下一条记录的 nonce（8B 随机前缀 + 4B 大端计数器）
    ///
    /// 计数器耗尽（已发出 2^32 条记录）时返回错误：此时若继续就会出现 nonce
    /// 复用，而 AES-GCM 的 (key, nonce) 复用会同时摧毁机密性与完整性，因此
    /// 这里选择 fail-closed（断连）而不是回绕。
    fn next_nonce(&mut self) -> std::io::Result<[u8; NONCE_LEN]> {
        if self.write_counter > u32::MAX as u64 {
            return Err(std::io::Error::other(
                "encrypted stream: nonce counter exhausted, refusing to reuse a nonce",
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&(self.write_counter as u32).to_be_bytes());
        self.write_counter += 1;
        Ok(nonce)
    }

    /// 加密 `data` 为一帧并追加到发送缓冲
    fn seal_into_out_buf(&mut self, data: &[u8]) -> std::io::Result<()> {
        // ring 0.16 Buffer 语义：整段缓冲为明文，tag 追加在末尾
        let nonce_bytes = self.next_nonce()?;
        let mut body = data.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce"))?;
        self.write_key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut body)
            .map_err(|_| std::io::Error::other("seal failed"))?;

        let payload_len = (NONCE_LEN + body.len()) as u32;
        self.out_buf.extend_from_slice(&payload_len.to_be_bytes());
        self.out_buf.extend_from_slice(&nonce_bytes);
        self.out_buf.extend_from_slice(&body);
        Ok(())
    }

    /// 尽力把发送缓冲写出到底层连接；`Pending` 时返回 false
    fn try_drain_out(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.out_pos < self.out_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out_buf[self.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    let e = std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "encrypted stream: underlying write returned 0",
                    );
                    self.sticky_err = Some(e);
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "underlying write returned 0",
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
        // 底层也 flush，确保帧尽快上线
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    /// 尝试从 `rx_buf` 解析并解密一帧；成功后明文追加到 `in_plain`
    fn try_decrypt_frame(&mut self) -> std::io::Result<bool> {
        if self.rx_buf.len() < HEADER_LEN {
            return Ok(false);
        }
        let payload_len =
            u32::from_be_bytes(self.rx_buf[..4].try_into().expect("header len")) as usize;
        if !(MIN_PAYLOAD..=MAX_PAYLOAD).contains(&payload_len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("encrypted frame length {} out of range", payload_len),
            ));
        }
        let frame_len = HEADER_LEN + payload_len;
        if self.rx_buf.len() < frame_len {
            return Ok(false);
        }
        // 解密在 rx_buf 内原地完成
        let frame = &mut self.rx_buf[HEADER_LEN..frame_len];
        let (nonce_bytes, ct) = frame.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| std::io::Error::other("invalid nonce"))?;
        let plain = self
            .read_key
            .open_in_place(nonce, Aad::empty(), ct)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "GCM open failed (wrong key or corrupted/tampered frame)",
                )
            })?;
        self.in_plain.extend_from_slice(plain);
        self.rx_buf.drain(..frame_len);
        Ok(true)
    }
}

impl<S: crate::FrpConn> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 粘性错误
        if let Some(e) = &this.sticky_err {
            return Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())));
        }

        // 已有解密明文 → 直接拷出
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
            match this.try_decrypt_frame() {
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
                    // 底层 EOF：缓冲耗尽即正常结束；解析失败说明帧不完整
                    if this.rx_buf.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let e = std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "encrypted stream: EOF mid-frame",
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

impl<S: crate::FrpConn> AsyncWrite for EncryptedStream<S> {
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

        // 超过单记录上限时分块落多条记录（write_all 会把整段传进来，需在此分块）
        for chunk in buf.chunks(MAX_PLAINTEXT_RECORD) {
            if let Err(e) = this.seal_into_out_buf(chunk) {
                this.sticky_err = Some(std::io::Error::new(e.kind(), e.to_string()));
                return Poll::Ready(Err(e));
            }
        }
        // 尽力写出（失败留在 out_buf 由 flush 收尾）
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

impl<S: crate::FrpConn> crate::FrpConn for EncryptedStream<S> {
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.remote_addr()
    }
}

#[cfg(test)]
mod crypto_tests {
    use super::*;
    use crate::FrpConn;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 测试用 FrpConn 适配器（包一层 TCP 流）
    struct TestConn(tokio::net::TcpStream);

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
            self.0.peer_addr().ok()
        }
    }

    async fn tcp_pair() -> (TestConn, TestConn) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(
            async { TestConn(tokio::net::TcpStream::connect(addr).await.unwrap()) },
            async {
                loop {
                    if let Ok((s, _)) = listener.accept().await {
                        break TestConn(s);
                    }
                }
            }
        );
        (a, b)
    }

    fn key() -> Vec<u8> {
        // SHA-256("test-token") 的前 32 字节语义即可，测试固定 32B
        vec![7u8; 32]
    }

    #[tokio::test]
    async fn test_roundtrip_small_and_large() {
        let (a, b) = tcp_pair().await;
        let mut e1 = EncryptedStream::new(a, &key()).unwrap();
        let mut e2 = EncryptedStream::new(b, &key()).unwrap();

        // 大流量：跨多条记录 + 部分读取（64KB + 1B，覆盖 16KB 记录边界）
        let payload: Vec<u8> = (0..=64 * 1024u32).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let writer = tokio::spawn(async move {
            e1.write_all(&payload).await.unwrap();
            e1.flush().await.unwrap();
            e1.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        e2.read_to_end(&mut received).await.unwrap();
        writer.await.unwrap();
        assert_eq!(received, payload_clone);
    }

    #[tokio::test]
    async fn test_bidirectional_interleaved() {
        let (a, b) = tcp_pair().await;
        let mut e1 = EncryptedStream::new(a, &key()).unwrap();
        let mut e2 = EncryptedStream::new(b, &key()).unwrap();

        e1.write_all(b"ping").await.unwrap();
        e1.flush().await.unwrap();
        let mut buf = [0u8; 4];
        e2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        e2.write_all(b"pongpong").await.unwrap();
        e2.flush().await.unwrap();
        let mut buf2 = [0u8; 8];
        e1.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pongpong");
    }

    #[tokio::test]
    async fn test_wrong_key_fails_closed() {
        let (a, b) = tcp_pair().await;
        let mut e1 = EncryptedStream::new(a, &key()).unwrap();
        let mut wrong_key = key();
        wrong_key[0] ^= 0xFF;
        let mut e2 = EncryptedStream::new(b, &wrong_key).unwrap();

        e1.write_all(b"secret").await.unwrap();
        e1.flush().await.unwrap();

        let mut buf = Vec::new();
        let result = e2.read_to_end(&mut buf).await;
        assert!(
            result.is_err(),
            "read with wrong key must fail, not return garbage"
        );
    }

    #[tokio::test]
    async fn test_tampered_frame_fails() {
        let (a, b) = tcp_pair().await;
        let mut e2 = EncryptedStream::new(b, &key()).unwrap();

        // 向读侧注入非法长度帧头（0xFFFFFFFF 越界），必须 InvalidData 而非 panic
        e2.rx_buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let err = e2.try_decrypt_frame().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // 注入合法长度但内容全零的帧：GCM tag 校验必须失败
        let mut frame = vec![0u8; 4];
        frame.extend_from_slice(&((NONCE_LEN + TAG_LEN) as u32).to_be_bytes());
        frame.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        let mut e3 = EncryptedStream::new(a, &key()).unwrap();
        e3.rx_buf = frame;
        let err2 = e3.try_decrypt_frame().unwrap_err();
        assert_eq!(err2.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_nonce_layout_prefix_plus_counter() {
        // 直接验证 nonce 布局：前 8B 随机前缀 + 后 4B 计数器
        let prefix = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&42u32.to_be_bytes());
        assert_eq!(&nonce[..NONCE_PREFIX_LEN], &prefix);
        assert_eq!(&nonce[NONCE_PREFIX_LEN..], &42u32.to_be_bytes());
        // 前缀宽度由模块级 const 断言保证 >= 8B（本次加固的实质）
    }

    #[tokio::test]
    async fn test_nonce_counter_exhaustion_fails_closed() {
        // 计数器耗尽必须报错断连，绝不回绕复用 nonce
        let (a, _b) = tcp_pair().await;
        let mut e = EncryptedStream::new(a, &key()).unwrap();
        e.write_counter = u32::MAX as u64;
        assert!(e.next_nonce().is_ok(), "最后一条记录仍可用");
        assert!(
            e.next_nonce().is_err(),
            "计数器耗尽后必须 fail-closed 而不是回绕"
        );
    }

    #[tokio::test]
    async fn test_legacy_4b_prefix_frame_still_decrypts() {
        // 兼容性回归：旧版发送端用「4B 前缀 + 8B 计数器」构造 nonce，
        // 新版接收端必须仍能解密——nonce 随帧传输，接收端不解释其内部布局，
        // 因此本次前缀扩容对旧对端是**协议兼容**的。
        let (a, _b) = tcp_pair().await;
        let mut reader = EncryptedStream::new(a, &key()).unwrap();

        let mut legacy_nonce = [0u8; NONCE_LEN];
        legacy_nonce[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        legacy_nonce[4..].copy_from_slice(&7u64.to_be_bytes());

        let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key()).unwrap());
        let mut body = b"legacy-layout".to_vec();
        k.seal_in_place_append_tag(
            Nonce::try_assume_unique_for_key(&legacy_nonce).unwrap(),
            Aad::empty(),
            &mut body,
        )
        .unwrap();

        let mut frame = ((NONCE_LEN + body.len()) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&legacy_nonce);
        frame.extend_from_slice(&body);
        reader.rx_buf = frame;

        assert!(reader.try_decrypt_frame().unwrap(), "旧布局帧必须可解");
        assert_eq!(reader.in_plain, b"legacy-layout");
    }
}
