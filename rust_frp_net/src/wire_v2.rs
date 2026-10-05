//! wire protocol v2：魔数 + 帧化握手 + 能力协商 + 方向性 AEAD 控制通道
//!
//! 对齐原版 frp `pkg/proto/wire` 的 v2 线协议设计，用于替代 v1 的裸明文控制通道：
//!
//! ```text
//! 客户端                                         服务端
//!   |                                              |
//!   |  MAGIC_V2 ("FRP\x00\x02\r\n", 8B)             |
//!   |--- Frame{ClientHello} --------------------->|
//!   |                                              |  校验能力 → 选算法 → 生成 server_random
//!   |<-- Frame{ServerHello} ----------------------|
//!   |                                              |
//!   |  cryptoContext = SHA-256 转录哈希              |
//!   |  readKey/writeKey = HKDF-SHA256(base, 转录)   |
//!   |  （client-to-server / server-to-client 分离）  |
//!   |                                              |
//!   |<==== 之后全部控制消息经方向性 AEAD 加密 ====>|
//! ```
//!
//! # 帧格式
//!
//! ```text
//! [2B 类型][2B 标志][4B 载荷长度][载荷]
//! ```
//!
//! - 类型：`1 = ClientHello` / `2 = ServerHello` / `16 = Message`；
//! - 标志：当前必须为 0（保留位，非 0 视为协议错误）；
//! - 载荷长度上限 [`DEFAULT_MAX_FRAME_PAYLOAD_SIZE`]（64KB）。
//!
//! # 密钥派生
//!
//! 基础密钥为 `SHA-256(token)`（与 `use_encryption` 同源）。控制通道读写方向
//! 分别派生独立密钥，从根本上排除双向复用同一 `(key, nonce)` 组合：
//!
//! ```text
//! info = "frp wire v2 control aead " + algorithm + " " + direction
//! key  = HKDF-SHA256(ikm = base_key, salt = transcript_hash, info)
//! ```
//!
//! `transcript_hash` 绑定本次握手的字节（`SHA-256(label || CH || SH)`），
//! 使密钥与协商内容唯一绑定。
//!
//! # 算法
//!
//! 目前仅 `aes-256-gcm`（见 [`SUPPORTED_AEAD_ALGORITHMS`]）；`xchacha20-poly1305`
//! 为路线图项，协商时不会被选中。

use crate::crypto::EncryptedStream;
use crate::FrpConn;
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// v2 握手魔数（8 字节，`FRP` + 版本号 2 + CRLF）
pub const MAGIC_V2: &[u8] = b"FRP\x00\x02\r\n";

/// 帧类型：ClientHello
pub const FRAME_TYPE_CLIENT_HELLO: u16 = 1;
/// 帧类型：ServerHello
pub const FRAME_TYPE_SERVER_HELLO: u16 = 2;
/// 帧类型：普通消息帧（控制平面消息）
pub const FRAME_TYPE_MESSAGE: u16 = 16;

/// 消息编解码器名称（JSON）
pub const MESSAGE_CODEC_JSON: &str = "json";
/// UDP 数据包编解码器名称（二进制）
pub const UDP_PACKET_CODEC_BINARY: &str = "binary-v1";

/// 单帧载荷上限（64KB）
pub const DEFAULT_MAX_FRAME_PAYLOAD_SIZE: u32 = 64 * 1024;

/// AEAD 算法名：AES-256-GCM
pub const AEAD_ALGORITHM_AES_256_GCM: &str = "aes-256-gcm";
/// AEAD 算法名：XChaCha20-Poly1305（**尚未实现**，仅作协商占位）
pub const AEAD_ALGORITHM_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

/// 本实现实际支持的 AEAD 算法集合
///
/// 只有出现在此列表中的算法才会被协商选中；客户端在 ClientHello 中只声明
/// 这里列出的算法，避免「协商成功但无法加密」的假成功。
pub const SUPPORTED_AEAD_ALGORITHMS: &[&str] = &[AEAD_ALGORITHM_AES_256_GCM];

/// 随机数长度（client_random / server_random 均为 32 字节）
pub const CRYPTO_RANDOM_SIZE: usize = 32;
/// 派生密钥长度（AES-256 需 32 字节）
pub const AEAD_KEY_SIZE: usize = 32;

const CRYPTO_TRANSCRIPT_LABEL: &str = "frp wire v2 crypto transcript";
const AEAD_CONTROL_HKDF_INFO_PREFIX: &str = "frp wire v2 control aead";
const AEAD_DIRECTION_CLIENT_TO_SERVER: &str = "client-to-server";
const AEAD_DIRECTION_SERVER_TO_CLIENT: &str = "server-to-client";

/// v2 线协议错误
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wire v2 protocol error: {0}")]
    Protocol(String),
}

impl From<WireError> for io::Error {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

/// 单个 v2 帧
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// 帧类型（[`FRAME_TYPE_CLIENT_HELLO`] / [`FRAME_TYPE_SERVER_HELLO`] / [`FRAME_TYPE_MESSAGE`]）
    pub type_id: u16,
    /// 标志位（当前恒为 0）
    pub flags: u16,
    /// 载荷
    pub payload: Vec<u8>,
}

impl Frame {
    /// 构造一个 JSON 载荷帧
    pub fn json<T: Serialize>(type_id: u16, value: &T) -> Result<Self, WireError> {
        Ok(Self {
            type_id,
            flags: 0,
            payload: serde_json::to_vec(value)?,
        })
    }

    /// 解析载荷为 JSON
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, WireError> {
        Ok(serde_json::from_slice(&self.payload)?)
    }
}

/// 从流中读取一个 v2 帧
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, WireError> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;

    let type_id = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    if flags != 0 {
        return Err(WireError::Protocol(format!(
            "unsupported frame flags: {flags}"
        )));
    }
    if length > DEFAULT_MAX_FRAME_PAYLOAD_SIZE {
        return Err(WireError::Protocol(format!(
            "frame payload length {length} exceeds limit {DEFAULT_MAX_FRAME_PAYLOAD_SIZE}"
        )));
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Frame {
        type_id,
        flags,
        payload,
    })
}

/// 向流中写入一个 v2 帧
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), WireError> {
    if frame.flags != 0 {
        return Err(WireError::Protocol(format!(
            "unsupported frame flags: {}",
            frame.flags
        )));
    }
    if frame.payload.len() > DEFAULT_MAX_FRAME_PAYLOAD_SIZE as usize {
        return Err(WireError::Protocol(format!(
            "frame payload length {} exceeds limit {DEFAULT_MAX_FRAME_PAYLOAD_SIZE}",
            frame.payload.len()
        )));
    }

    let mut header = [0u8; 8];
    header[0..2].copy_from_slice(&frame.type_id.to_be_bytes());
    header[2..4].copy_from_slice(&frame.flags.to_be_bytes());
    header[4..8].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    Ok(())
}

/// 写入 v2 握手魔数
pub async fn write_magic<W: AsyncWrite + Unpin>(writer: &mut W) -> io::Result<()> {
    writer.write_all(MAGIC_V2).await
}

/// 读取 [`MAGIC_V2`] 长度的前缀字节，判断对方是否为 v2
///
/// 返回 `(读到的字节, 是否为 v2)`。**总是消费** `MAGIC_V2.len()` 字节；
/// 若非 v2，调用方须用 [`crate::PrefixedStream`] 把这批字节回放给 v1 解析路径。
pub async fn check_magic<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(Vec<u8>, bool)> {
    let mut buf = vec![0u8; MAGIC_V2.len()];
    reader.read_exact(&mut buf).await?;
    let is_v2 = buf == MAGIC_V2;
    Ok((buf, is_v2))
}

/// 客户端引导信息（供服务端日志/策略使用）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapInfo {
    /// 传输协议名（tcp / kcp / quic / websocket / wss）
    #[serde(default)]
    pub transport: String,
    /// 是否叠加 TLS
    #[serde(default)]
    pub tls: bool,
    /// 是否启用 tcp_mux
    #[serde(default, rename = "tcpMux")]
    pub tcp_mux: bool,
}

/// 消息层能力
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageCapabilities {
    /// 支持的消息编解码器
    #[serde(default)]
    pub codecs: Vec<String>,
    /// 支持的 UDP 数据包编解码器
    #[serde(default, rename = "udpPacketCodecs")]
    pub udp_packet_codecs: Vec<String>,
}

/// 加密层能力
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoCapabilities {
    /// 支持的 AEAD 算法（按偏好排序）
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// 客户端随机数（32 字节，base64 编码，对齐原版 `[]byte` JSON 语义）
    #[serde(default, rename = "clientRandom", with = "b64_bytes")]
    pub client_random: Vec<u8>,
}

/// 客户端能力集合
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub message: MessageCapabilities,
    #[serde(default)]
    pub crypto: CryptoCapabilities,
}

/// ClientHello 帧载荷
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    #[serde(default)]
    pub bootstrap: BootstrapInfo,
    #[serde(default)]
    pub capabilities: ClientCapabilities,
}

/// 消息层选择结果
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSelection {
    #[serde(default)]
    pub codec: String,
    #[serde(default, rename = "udpPacketCodec")]
    pub udp_packet_codec: String,
}

/// 加密层选择结果
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSelection {
    #[serde(default)]
    pub algorithm: String,
    /// 服务端随机数（32 字节，base64 编码）
    #[serde(default, rename = "serverRandom", with = "b64_bytes")]
    pub server_random: Vec<u8>,
}

/// 服务端选择集合
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSelection {
    #[serde(default)]
    pub message: MessageSelection,
    #[serde(default)]
    pub crypto: CryptoSelection,
}

/// ServerHello 帧载荷
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    #[serde(default)]
    pub selected: ServerSelection,
    /// 协商失败原因（非空表示拒绝本次 v2 握手）
    #[serde(default)]
    pub error: String,
}

/// 生成客户端 ClientHello（含随机数）
pub fn new_client_hello(bootstrap: BootstrapInfo) -> Result<ClientHello, WireError> {
    let client_random = crypto_random()?;
    Ok(ClientHello {
        bootstrap,
        capabilities: ClientCapabilities {
            message: MessageCapabilities {
                codecs: vec![MESSAGE_CODEC_JSON.to_string()],
                udp_packet_codecs: vec![UDP_PACKET_CODEC_BINARY.to_string()],
            },
            crypto: CryptoCapabilities {
                algorithms: SUPPORTED_AEAD_ALGORITHMS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                client_random,
            },
        },
    })
}

/// 由 ClientHello 生成 ServerHello（校验能力 → 选算法 → 生成随机数）
pub fn new_server_hello(hello: &ClientHello) -> Result<ServerHello, WireError> {
    validate_client_hello(hello)?;
    let algorithm = select_aead_algorithm(&hello.capabilities.crypto.algorithms)
        .ok_or_else(|| WireError::Protocol("no supported crypto algorithm".to_string()))?;
    let server_random = crypto_random()?;
    Ok(ServerHello {
        selected: ServerSelection {
            message: MessageSelection {
                codec: MESSAGE_CODEC_JSON.to_string(),
                udp_packet_codec: select_udp_packet_codec(
                    &hello.capabilities.message.udp_packet_codecs,
                ),
            },
            crypto: CryptoSelection {
                algorithm: algorithm.to_string(),
                server_random,
            },
        },
        error: String::new(),
    })
}

/// 校验客户端能力：必须支持 JSON 消息编解码器、随机数长度正确、至少一种共同算法
pub fn validate_client_hello(hello: &ClientHello) -> Result<(), WireError> {
    if !hello
        .capabilities
        .message
        .codecs
        .iter()
        .any(|c| c == MESSAGE_CODEC_JSON)
    {
        return Err(WireError::Protocol("unsupported message codec".to_string()));
    }
    validate_crypto_capabilities(&hello.capabilities.crypto)
}

/// 校验加密能力
pub fn validate_crypto_capabilities(cap: &CryptoCapabilities) -> Result<(), WireError> {
    if cap.client_random.len() != CRYPTO_RANDOM_SIZE {
        return Err(WireError::Protocol(format!(
            "invalid crypto client random length {}, want {CRYPTO_RANDOM_SIZE}",
            cap.client_random.len()
        )));
    }
    if select_aead_algorithm(&cap.algorithms).is_none() {
        return Err(WireError::Protocol(
            "no supported crypto algorithm".to_string(),
        ));
    }
    Ok(())
}

/// 客户端校验 ServerHello：编解码器与算法必须是自己声明过的、随机数长度正确
pub fn validate_server_hello_for_client(
    client: &ClientHello,
    server: &ServerHello,
) -> Result<(), WireError> {
    if server.selected.message.codec != MESSAGE_CODEC_JSON {
        return Err(WireError::Protocol(format!(
            "unsupported selected message codec: {}",
            server.selected.message.codec
        )));
    }
    let udp_codec = &server.selected.message.udp_packet_codec;
    if !udp_codec.is_empty() {
        if udp_codec != UDP_PACKET_CODEC_BINARY {
            return Err(WireError::Protocol(format!(
                "unsupported selected UDP packet codec: {udp_codec}"
            )));
        }
        if !client
            .capabilities
            .message
            .udp_packet_codecs
            .iter()
            .any(|c| c == udp_codec)
        {
            return Err(WireError::Protocol(format!(
                "selected UDP packet codec was not advertised by client: {udp_codec}"
            )));
        }
    }
    let algo = &server.selected.crypto.algorithm;
    if !is_supported_aead_algorithm(algo) {
        return Err(WireError::Protocol(format!(
            "unknown selected crypto algorithm: {algo}"
        )));
    }
    if !client
        .capabilities
        .crypto
        .algorithms
        .iter()
        .any(|a| a == algo)
    {
        return Err(WireError::Protocol(format!(
            "selected crypto algorithm was not advertised by client: {algo}"
        )));
    }
    if server.selected.crypto.server_random.len() != CRYPTO_RANDOM_SIZE {
        return Err(WireError::Protocol(format!(
            "invalid crypto server random length {}, want {CRYPTO_RANDOM_SIZE}",
            server.selected.crypto.server_random.len()
        )));
    }
    Ok(())
}

/// 是否为本实现支持的 AEAD 算法
pub fn is_supported_aead_algorithm(algorithm: &str) -> bool {
    SUPPORTED_AEAD_ALGORITHMS.contains(&algorithm)
}

/// 按客户端偏好顺序选出第一个双方都支持的算法
pub fn select_aead_algorithm(client_algorithms: &[String]) -> Option<&'static str> {
    client_algorithms
        .iter()
        .find_map(|a| SUPPORTED_AEAD_ALGORITHMS.iter().find(|s| **s == a.as_str()))
        .copied()
}

fn select_udp_packet_codec(codecs: &[String]) -> String {
    if codecs.iter().any(|c| c == UDP_PACKET_CODEC_BINARY) {
        UDP_PACKET_CODEC_BINARY.to_string()
    } else {
        String::new()
    }
}

/// 本次握手确定下来的加密上下文
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoContext {
    /// 选中的 AEAD 算法
    pub algorithm: String,
    /// 握手转录哈希（`SHA-256(label || CH || SH)`）
    pub transcript_hash: Vec<u8>,
}

/// 服务端：由 ClientHello / ServerHello 载荷构造加密上下文
pub fn new_crypto_context(
    algorithm: &str,
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
) -> CryptoContext {
    CryptoContext {
        algorithm: algorithm.to_string(),
        transcript_hash: hash_crypto_transcript(client_hello_payload, server_hello_payload),
    }
}

/// 客户端：解析两端 Hello 载荷、校验 ServerHello，并构造加密上下文
pub fn new_client_crypto_context(
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
) -> Result<CryptoContext, WireError> {
    let client: ClientHello = serde_json::from_slice(client_hello_payload)?;
    let server: ServerHello = serde_json::from_slice(server_hello_payload)?;
    validate_server_hello_for_client(&client, &server)?;
    Ok(new_crypto_context(
        &server.selected.crypto.algorithm,
        client_hello_payload,
        server_hello_payload,
    ))
}

/// 计算握手转录哈希（`SHA-256(label || 长度前缀(client hello) || 长度前缀(server hello))`）
pub fn hash_crypto_transcript(client_hello_payload: &[u8], server_hello_payload: &[u8]) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    write_transcript_part(&mut ctx, "client hello", client_hello_payload);
    write_transcript_part(&mut ctx, "server hello", server_hello_payload);
    ctx.finish().as_ref().to_vec()
}

fn write_transcript_part(ctx: &mut digest::Context, label: &str, payload: &[u8]) {
    ctx.update(&[0]);
    ctx.update(label.as_bytes());
    ctx.update(&[0]);
    ctx.update(&(payload.len() as u64).to_be_bytes());
    ctx.update(payload);
}

/// 派生单向控制通道密钥
pub fn derive_control_key(
    base_key: &[u8],
    algorithm: &str,
    transcript_hash: &[u8],
    direction: &str,
) -> Vec<u8> {
    let info = format!("{AEAD_CONTROL_HKDF_INFO_PREFIX} {algorithm} {direction}");
    hkdf_sha256(base_key, transcript_hash, info.as_bytes(), AEAD_KEY_SIZE)
}

/// 派生双向控制通道密钥，返回 `(client→server, server→client)`
pub fn derive_control_keys(
    base_key: &[u8],
    algorithm: &str,
    transcript_hash: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let c2s = derive_control_key(
        base_key,
        algorithm,
        transcript_hash,
        AEAD_DIRECTION_CLIENT_TO_SERVER,
    );
    let s2c = derive_control_key(
        base_key,
        algorithm,
        transcript_hash,
        AEAD_DIRECTION_SERVER_TO_CLIENT,
    );
    (c2s, s2c)
}

/// HKDF-SHA256（RFC 5869）。单一输出块即可满足 32 字节需求，此处按需扩展。
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    // Extract
    let salt_key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let prk = hmac::sign(&salt_key, ikm);
    let prk_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());

    // Expand
    let mut okm = Vec::with_capacity(out_len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < out_len {
        let mut ctx = hmac::Context::with_key(&prk_key);
        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[counter]);
        prev = ctx.sign().as_ref().to_vec();
        okm.extend_from_slice(&prev);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(out_len);
    okm
}

/// 握手角色（决定读写密钥方向）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadRole {
    /// 客户端：读 server→client，写 client→server
    Client,
    /// 服务端：读 client→server，写 server→client
    Server,
}

/// 按角色计算 `(read_key, write_key)`
pub fn control_keys_for_role(
    base_key: &[u8],
    algorithm: &str,
    transcript_hash: &[u8],
    role: AeadRole,
) -> (Vec<u8>, Vec<u8>) {
    let (c2s, s2c) = derive_control_keys(base_key, algorithm, transcript_hash);
    match role {
        AeadRole::Client => (s2c, c2s),
        AeadRole::Server => (c2s, s2c),
    }
}

fn crypto_random() -> Result<Vec<u8>, WireError> {
    let mut buf = vec![0u8; CRYPTO_RANDOM_SIZE];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| WireError::Protocol("failed to generate crypto random".to_string()))?;
    Ok(buf)
}

/// 客户端握手：写魔数 → 发 ClientHello → 读 ServerHello → 派生方向性密钥 → 包装 AEAD
///
/// 返回的 [`EncryptedStream`] 已按 client 角色选用读写密钥；此后（含 Login）
/// 全部控制消息都应通过它读写。
pub async fn client_handshake<S: FrpConn>(
    mut conn: S,
    base_key: &[u8],
    bootstrap: BootstrapInfo,
) -> Result<EncryptedStream<S>, WireError> {
    write_magic(&mut conn).await?;

    let hello = new_client_hello(bootstrap)?;
    let hello_frame = Frame::json(FRAME_TYPE_CLIENT_HELLO, &hello)?;
    write_frame(&mut conn, &hello_frame).await?;

    let reply = read_frame(&mut conn).await?;
    if reply.type_id != FRAME_TYPE_SERVER_HELLO {
        return Err(WireError::Protocol(format!(
            "unexpected frame type {}, want {FRAME_TYPE_SERVER_HELLO}",
            reply.type_id
        )));
    }
    let server_hello: ServerHello = reply.decode()?;
    if !server_hello.error.is_empty() {
        return Err(WireError::Protocol(format!(
            "server rejected wire v2 handshake: {}",
            server_hello.error
        )));
    }

    let context = new_client_crypto_context(&hello_frame.payload, &reply.payload)?;
    let (read_key, write_key) = control_keys_for_role(
        base_key,
        &context.algorithm,
        &context.transcript_hash,
        AeadRole::Client,
    );
    EncryptedStream::new_directional(conn, &read_key, &write_key).map_err(WireError::Io)
}

/// 服务端握手：读 ClientHello → 发 ServerHello → 派生方向性密钥 → 包装 AEAD
///
/// 调用前须已通过 [`check_magic`] 确认对方发送了 v2 魔数（魔数字节已被消费）。
pub async fn server_handshake<S: FrpConn>(
    mut conn: S,
    base_key: &[u8],
) -> Result<EncryptedStream<S>, WireError> {
    let hello_frame = read_frame(&mut conn).await?;
    if hello_frame.type_id != FRAME_TYPE_CLIENT_HELLO {
        return Err(WireError::Protocol(format!(
            "unexpected frame type {}, want {FRAME_TYPE_CLIENT_HELLO}",
            hello_frame.type_id
        )));
    }
    let client_hello: ClientHello = hello_frame.decode()?;

    let server_hello = match new_server_hello(&client_hello) {
        Ok(sh) => sh,
        Err(e) => {
            // 尽力告知对方拒绝原因（此帧仍为明文）
            let rejected = ServerHello {
                selected: ServerSelection::default(),
                error: e.to_string(),
            };
            if let Ok(frame) = Frame::json(FRAME_TYPE_SERVER_HELLO, &rejected) {
                let _ = write_frame(&mut conn, &frame).await;
            }
            return Err(e);
        }
    };

    let reply_frame = Frame::json(FRAME_TYPE_SERVER_HELLO, &server_hello)?;
    write_frame(&mut conn, &reply_frame).await?;

    let context = new_crypto_context(
        &server_hello.selected.crypto.algorithm,
        &hello_frame.payload,
        &reply_frame.payload,
    );
    let (read_key, write_key) = control_keys_for_role(
        base_key,
        &context.algorithm,
        &context.transcript_hash,
        AeadRole::Server,
    );
    EncryptedStream::new_directional(conn, &read_key, &write_key).map_err(WireError::Io)
}

/// `Vec<u8>` 的 base64（标准字母表）序列化
///
/// 对齐原版 frp 中 `[]byte` 经 `encoding/json` 编码为 base64 字符串的语义。
mod b64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&text)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod wire_v2_tests {
    use super::*;

    fn bootstrap() -> BootstrapInfo {
        BootstrapInfo {
            transport: "tcp".to_string(),
            tls: true,
            tcp_mux: true,
        }
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frame = Frame {
            type_id: FRAME_TYPE_MESSAGE,
            flags: 0,
            payload: b"hello frame".to_vec(),
        };
        let f2 = frame.clone();
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &f2).await.unwrap();
        });
        let got = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, frame);
    }

    #[tokio::test]
    async fn frame_rejects_nonzero_flags_and_oversize() {
        // 写侧拒绝非 0 标志
        let mut sink = Vec::new();
        let bad = Frame {
            type_id: 1,
            flags: 1,
            payload: vec![],
        };
        assert!(write_frame(&mut sink, &bad).await.is_err());

        // 读侧拒绝非 0 标志
        let mut raw = Vec::new();
        raw.extend_from_slice(&FRAME_TYPE_MESSAGE.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        let mut reader: &[u8] = &raw;
        assert!(read_frame(&mut reader).await.is_err());

        // 读侧拒绝超限长度（声明 > 64KB）
        let mut raw = Vec::new();
        raw.extend_from_slice(&FRAME_TYPE_MESSAGE.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&(DEFAULT_MAX_FRAME_PAYLOAD_SIZE + 1).to_be_bytes());
        let mut reader: &[u8] = &raw;
        assert!(read_frame(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn check_magic_detects_v2_and_replays_otherwise() {
        // 魔数 → true
        let mut buf: Vec<u8> = MAGIC_V2.to_vec();
        buf.extend_from_slice(b"rest");
        let mut cursor: &[u8] = &buf;
        let (prefix, is_v2) = check_magic(&mut cursor).await.unwrap();
        assert!(is_v2);
        assert_eq!(prefix, MAGIC_V2);

        // v1 首帧（4B 长度 + JSON）→ false，且前缀被完整读出以便回放
        let mut buf = Vec::new();
        buf.extend_from_slice(&20u32.to_be_bytes());
        buf.extend_from_slice(b"{\"Login\":{}}");
        let mut cursor: &[u8] = &buf;
        let (prefix, is_v2) = check_magic(&mut cursor).await.unwrap();
        assert!(!is_v2);
        assert_eq!(prefix.len(), MAGIC_V2.len());
        assert_eq!(&prefix[..4], &20u32.to_be_bytes());
    }

    #[test]
    fn server_hello_selects_supported_algorithm() {
        let hello = new_client_hello(bootstrap()).unwrap();
        assert_eq!(
            hello.capabilities.crypto.client_random.len(),
            CRYPTO_RANDOM_SIZE
        );
        let reply = new_server_hello(&hello).unwrap();
        assert!(reply.error.is_empty());
        assert_eq!(reply.selected.crypto.algorithm, AEAD_ALGORITHM_AES_256_GCM);
        assert_eq!(reply.selected.message.codec, MESSAGE_CODEC_JSON);
        assert_eq!(
            reply.selected.message.udp_packet_codec,
            UDP_PACKET_CODEC_BINARY
        );
        assert!(validate_server_hello_for_client(&hello, &reply).is_ok());
    }

    #[test]
    fn validate_client_hello_rejects_bad_caps() {
        // 随机数长度错误
        let mut hello = new_client_hello(bootstrap()).unwrap();
        hello.capabilities.crypto.client_random = vec![0u8; 31];
        assert!(validate_client_hello(&hello).is_err());

        // 不含共同算法
        let mut hello = new_client_hello(bootstrap()).unwrap();
        hello.capabilities.crypto.algorithms = vec!["rsa-oaep".to_string()];
        assert!(validate_client_hello(&hello).is_err());

        // 不支持 json 编解码器
        let mut hello = new_client_hello(bootstrap()).unwrap();
        hello.capabilities.message.codecs = vec!["protobuf".to_string()];
        assert!(validate_client_hello(&hello).is_err());
    }

    #[test]
    fn validate_server_hello_rejects_unadvertised_algorithm() {
        let hello = new_client_hello(bootstrap()).unwrap();
        let mut reply = new_server_hello(&hello).unwrap();
        reply.selected.crypto.algorithm = AEAD_ALGORITHM_XCHACHA20_POLY1305.to_string();
        assert!(validate_server_hello_for_client(&hello, &reply).is_err());

        // 随机数长度错误
        let mut reply = new_server_hello(&hello).unwrap();
        reply.selected.crypto.server_random = vec![0u8; 1];
        assert!(validate_server_hello_for_client(&hello, &reply).is_err());
    }

    #[test]
    fn transcript_hash_is_deterministic_and_bound_to_both_hellos() {
        let ch = b"client-hello-payload";
        let sh = b"server-hello-payload";
        let a = hash_crypto_transcript(ch, sh);
        let b = hash_crypto_transcript(ch, sh);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // 任一 Hello 变化都会改变转录哈希
        assert_ne!(a, hash_crypto_transcript(b"other", sh));
        assert_ne!(a, hash_crypto_transcript(ch, b"other"));
    }

    #[test]
    fn hkdf_matches_rfc5869_test_vector_case_1() {
        // RFC 5869 A.1：ikm=0x0b*22, salt=0x000102...0c, info=0xf0f1...f9, L=42
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected, "HKDF-SHA256 必须符合 RFC 5869 测试向量");
    }

    #[test]
    fn control_keys_are_directional_and_bound_to_transcript() {
        let base = vec![7u8; 32];
        let t = hash_crypto_transcript(b"ch", b"sh");
        let (c2s, s2c) = derive_control_keys(&base, AEAD_ALGORITHM_AES_256_GCM, &t);
        assert_eq!(c2s.len(), AEAD_KEY_SIZE);
        assert_eq!(s2c.len(), AEAD_KEY_SIZE);
        assert_ne!(c2s, s2c, "两个方向必须使用不同密钥");

        // 确定性
        let (c2s2, _) = derive_control_keys(&base, AEAD_ALGORITHM_AES_256_GCM, &t);
        assert_eq!(c2s, c2s2);

        // 换转录哈希 → 换密钥
        let t2 = hash_crypto_transcript(b"ch", b"sh2");
        let (c2s3, _) = derive_control_keys(&base, AEAD_ALGORITHM_AES_256_GCM, &t2);
        assert_ne!(c2s, c2s3);

        // 角色决定读写方向
        let (r_c, w_c) =
            control_keys_for_role(&base, AEAD_ALGORITHM_AES_256_GCM, &t, AeadRole::Client);
        let (r_s, w_s) =
            control_keys_for_role(&base, AEAD_ALGORITHM_AES_256_GCM, &t, AeadRole::Server);
        assert_eq!(r_c, w_s);
        assert_eq!(w_c, r_s);
        assert_eq!(r_c, s2c);
        assert_eq!(w_c, c2s);
    }

    /// 端到端：真实 TCP 上完成 v2 握手，并用方向性 AEAD 通道双向收发帧
    #[tokio::test]
    async fn handshake_and_encrypted_message_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_key = vec![0x42u8; 32];

        let server_key = base_key.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = Box::new(stream) as crate::AnyConn;
            let (prefix, is_v2) = check_magic(&mut stream).await.unwrap();
            assert!(is_v2, "客户端应发送 v2 魔数");
            assert_eq!(prefix, MAGIC_V2);
            let mut enc = server_handshake(stream, &server_key).await.unwrap();

            // 读客户端发来的消息帧
            let frame = read_frame(&mut enc).await.unwrap();
            assert_eq!(frame.type_id, FRAME_TYPE_MESSAGE);
            assert_eq!(frame.payload, b"ping-from-client".to_vec());

            // 回一条
            let reply = Frame {
                type_id: FRAME_TYPE_MESSAGE,
                flags: 0,
                payload: b"pong-from-server".to_vec(),
            };
            write_frame(&mut enc, &reply).await.unwrap();
            enc.flush().await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = Box::new(tcp) as crate::AnyConn;
        let mut enc = client_handshake(client, &base_key, bootstrap())
            .await
            .unwrap();

        let frame = Frame {
            type_id: FRAME_TYPE_MESSAGE,
            flags: 0,
            payload: b"ping-from-client".to_vec(),
        };
        write_frame(&mut enc, &frame).await.unwrap();
        enc.flush().await.unwrap();

        let reply = read_frame(&mut enc).await.unwrap();
        assert_eq!(reply.type_id, FRAME_TYPE_MESSAGE);
        assert_eq!(reply.payload, b"pong-from-server".to_vec());

        server.await.unwrap();
    }

    /// 错误基础密钥 → 解密失败（fail-closed，不返回垃圾数据）
    #[tokio::test]
    async fn mismatched_base_key_fails_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = Box::new(stream) as crate::AnyConn;
            let _ = check_magic(&mut stream).await.unwrap();
            // 使用错误的基础密钥
            let mut enc = server_handshake(stream, &[0x11u8; 32]).await.unwrap();
            let mut buf = [0u8; 8];
            // 首次读取必然失败（GCM 校验不过）
            let r = tokio::io::AsyncReadExt::read_exact(&mut enc, &mut buf).await;
            assert!(r.is_err(), "错误密钥下读取必须失败");
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = Box::new(tcp) as crate::AnyConn;
        let mut enc = client_handshake(client, &[0x22u8; 32], bootstrap())
            .await
            .unwrap();
        let frame = Frame {
            type_id: FRAME_TYPE_MESSAGE,
            flags: 0,
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let _ = write_frame(&mut enc, &frame).await;
        let _ = enc.flush().await;
        server.await.unwrap();
    }
}
