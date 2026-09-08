//! # STUN 客户端（RFC 5389 Binding Request，零依赖）
//!
//! 用于 XTCP P2P 打洞前的公网端点探测：
//!
//! 1. `discover_public_endpoint(socket, servers)` 用**给定的 UDP socket** 向 STUN
//!    服务器发送 Binding Request，从 XOR-MAPPED-ADDRESS 解析本 socket 的公网映射。
//! 2. **socket 保留复用**是 NAT 打洞的关键：探测与后续打洞/KCP 通信必须走同一
//!    socket，否则 NAT 会分配新映射导致探测结果作废。
//! 3. 服务器列表轮询，全部失败返回错误（上层回退服务器观察地址兜底）。
//!
//! ## 报文格式
//!
//! Binding Request（20 字节）：
//! ```text
//! 0                15 16               31
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |0 0 1     |        0x0001        |   length=0  |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                magic cookie 0x2112A442        |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |             transaction id (12 bytes)         |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```
//!
//! XOR-MAPPED-ADDRESS（type 0x0020）：
//! ```text//! 0                   15 16   23 24      31
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |     0x0020      |  length=8   | 0 |family|  x-port  |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                x-address (32 bits)             |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```
//! port ^ (cookie >> 16)，address ^ cookie。

use crate::NetError;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// RFC 5389 magic cookie
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// XOR-MAPPED-ADDRESS 属性类型
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// MAPPED-ADDRESS 属性类型（旧版服务器兼容）
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// Binding Request 消息类型
const MSG_BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response 消息类型
const MSG_BINDING_RESPONSE: u16 = 0x0101;

/// 内置公共 STUN 服务器（探测轮询，任一成功即返回）
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// 解析后的默认 STUN 服务器地址（DNS 解析失败的服务器跳过）
pub async fn default_stun_socket_addrs() -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for server in DEFAULT_STUN_SERVERS {
        match tokio::net::lookup_host(server).await {
            Ok(mut iter) => {
                if let Some(a) = iter.next() {
                    addrs.push(a);
                }
            }
            Err(e) => {
                log::debug!("STUN server {} DNS resolve failed: {}", server, e);
            }
        }
    }
    addrs
}

/// 构造 Binding Request 报文
fn build_binding_request(tx_id: [u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&MSG_BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // 属性长度 0
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&tx_id);
    msg
}

/// 从 Binding Response 提取 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS
fn parse_mapped_address(resp: &[u8]) -> Result<SocketAddr, NetError> {
    if resp.len() < 20 {
        return Err(NetError::Other("STUN response too short".into()));
    }
    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);
    if msg_type != MSG_BINDING_RESPONSE {
        return Err(NetError::Other(format!(
            "STUN unexpected response type: 0x{:04x}",
            msg_type
        )));
    }
    // 校验 magic cookie
    let cookie = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(NetError::Other(
            "STUN response magic cookie mismatch".into(),
        ));
    }

    let attr_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
    let mut offset = 20;
    let end = (20 + attr_len).min(resp.len());

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
        let len = u16::from_be_bytes([resp[offset + 2], resp[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + len;
        if value_end > resp.len() {
            return Err(NetError::Other("STUN attribute length overflow".into()));
        }
        let value = &resp[value_start..value_end];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS | ATTR_MAPPED_ADDRESS if len >= 8 => {
                let family = value[1];
                if family != 0x01 {
                    // 仅支持 IPv4（与本项目地址类型一致）
                    return Err(NetError::Other(format!(
                        "STUN unsupported address family: 0x{:02x}",
                        family
                    )));
                }
                let port = u16::from_be_bytes([value[2], value[3]]);
                let ip_bytes = [value[4], value[5], value[6], value[7]];
                let (port, ip) = if attr_type == ATTR_XOR_MAPPED_ADDRESS {
                    // XOR 解码：port ^ (cookie >> 16)，address ^ cookie
                    let x_port = port ^ (MAGIC_COOKIE >> 16) as u16;
                    let x_addr = u32::from_be_bytes(ip_bytes) ^ MAGIC_COOKIE;
                    (x_port, x_addr.to_be_bytes())
                } else {
                    (port, ip_bytes)
                };
                let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
                return Ok(addr);
            }
            _ => {}
        }
        // 属性 4 字节对齐
        offset = value_start + ((len + 3) & !3);
    }

    Err(NetError::Other(
        "STUN response has no XOR-MAPPED-ADDRESS".into(),
    ))
}

/// 用给定 UDP socket 探测公网端点（socket 保留复用，NAT 映射不变的关键）
///
/// 轮询 `servers`，任一成功即返回。全失败返回错误，
/// 上层回退服务器观察地址兜底。
pub async fn discover_public_endpoint(
    socket: Arc<UdpSocket>,
    servers: &[SocketAddr],
) -> Result<SocketAddr, NetError> {
    if servers.is_empty() {
        return Err(NetError::Other("no STUN servers configured".into()));
    }

    let mut last_err = String::new();
    for server in servers {
        match probe_one(socket.clone(), *server).await {
            Ok(addr) => return Ok(addr),
            Err(e) => {
                log::debug!("STUN probe {} failed: {}", server, e);
                last_err = format!("{}; {}: {}", last_err, server, e);
            }
        }
    }
    Err(NetError::Other(format!(
        "all STUN servers failed: {}",
        last_err
    )))
}

async fn probe_one(socket: Arc<UdpSocket>, server: SocketAddr) -> Result<SocketAddr, NetError> {
    // 随机 transaction id
    let mut tx_id = [0u8; 12];
    tx_id[..4].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    tx_id[4..].copy_from_slice(&rand::random::<u64>().to_be_bytes());
    let request = build_binding_request(tx_id);

    socket
        .send_to(&request, server)
        .await
        .map_err(|e| NetError::Other(format!("send: {}", e)))?;

    let mut buf = vec![0u8; 1024];
    let timeout = tokio::time::Duration::from_secs(3);
    let (n, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| NetError::Other("STUN response timeout".into()))?
        .map_err(|e| NetError::Other(format!("recv: {}", e)))?;

    // 校验 transaction id 一致性
    if n < 20 || buf[4..16] != tx_id[..] && buf[8..20] != tx_id[..] {
        // 标准 RFC 5389 响应：cookie 在 [4..8]，tx_id 在 [8..20]
        if n < 20 || buf[8..20] != tx_id[..] {
            return Err(NetError::Other("STUN transaction id mismatch".into()));
        }
    }

    parse_mapped_address(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 STUN Binding Success Response（XOR-MAPPED-ADDRESS）
    fn build_response(tx_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let ip = match mapped.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => panic!("test only supports ipv4"),
        };
        let x_port = (mapped.port() as u16) ^ (MAGIC_COOKIE >> 16) as u16;
        let x_addr = u32::from_be_bytes(ip) ^ MAGIC_COOKIE;

        let mut attr = vec![0u8; 8];
        attr[0..2].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr[2..4].copy_from_slice(&8u16.to_be_bytes());
        attr[4] = 0;
        attr[5] = 0x01; // IPv4
        attr[6..8].copy_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr.to_be_bytes());

        let mut msg = Vec::with_capacity(20 + attr.len());
        msg.extend_from_slice(&MSG_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&tx_id);
        msg.extend_from_slice(&attr);
        msg
    }

    /// mock STUN 服务器：收到请求后回 XOR-MAPPED-ADDRESS = 请求来源地址
    async fn spawn_mock_stun() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        if n < 20 {
                            continue;
                        }
                        let mut tx_id = [0u8; 12];
                        tx_id.copy_from_slice(&buf[8..20]);
                        let resp = build_response(tx_id, src);
                        let _ = socket.send_to(&resp, src).await;
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn test_stun_discover_with_mock_server() {
        let (stun_addr, _handle) = spawn_mock_stun().await;
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = client.local_addr().unwrap();

        // mock 服务器返回请求来源地址（本机回环即本地地址）
        let public = discover_public_endpoint(client.clone(), &[stun_addr])
            .await
            .expect("discover");
        assert_eq!(public.port(), local.port());

        // 复用同一 socket 再次探测，映射不变
        let again = discover_public_endpoint(client, &[stun_addr])
            .await
            .unwrap();
        assert_eq!(public, again);
    }

    #[tokio::test]
    async fn test_stun_all_servers_failed() {
        // 无监听的端口 → 全部超时/拒绝 → 错误
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dead = "127.0.0.1:1".parse().unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            discover_public_endpoint(client, &[dead]),
        )
        .await;
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_parse_mapped_address_xor() {
        let tx_id = [7u8; 12];
        let mapped: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let resp = build_response(tx_id, mapped);
        let parsed = parse_mapped_address(&resp).expect("parse");
        assert_eq!(parsed, mapped);
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert!(parse_mapped_address(&[0u8; 10]).is_err());
        // 错误消息类型
        let mut msg = vec![0u8; 24];
        msg[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        assert!(parse_mapped_address(&msg).is_err());
    }
}
