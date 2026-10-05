//! PROXY protocol 头构造（v1 文本 / v2 二进制）
//!
//! 对齐原版 frp `pkg/util/net/proxyprotocol.go`（基于 `pires/go-proxyproto` 的
//! `HeaderProxyFromAddrs`）：frpc 在连接本地服务前写入 PROXY protocol 头，
//! 让 nginx/haproxy 等本地服务获取真实访问者 IP。
//!
//! - **v1**：文本格式 `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`；
//! - **v2**：二进制格式 —— 12 字节签名 + `[ver|cmd][fam|proto][len][地址载荷]`；
//! - 源地址无法解析为 IP 时退化为 `PROXY UNKNOWN\r\n`（v1）/ LOCAL 命令帧（v2），
//!   与规范中「连接信息不可用」的语义一致。
//!
//! 版本选择与原版一致：`"v1"` → v1，其余（含 `"v2"`）→ v2。

/// v2 协议签名（12 字节）：`\r\n\r\n\0\r\nQUIT\n`
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// v2 协议版本号（高 4 位）
const V2_VERSION: u8 = 0x20;

/// v2 命令：PROXY（携带真实连接信息）
const V2_CMD_PROXY: u8 = 0x01;
/// v2 命令：LOCAL（连接信息不可用）
const V2_CMD_LOCAL: u8 = 0x00;

/// v2 地址族：IPv4
const V2_FAMILY_INET: u8 = 0x10;
/// v2 地址族：IPv6
const V2_FAMILY_INET6: u8 = 0x20;
/// v2 协议：STREAM（TCP）
const V2_PROTO_STREAM: u8 = 0x01;

/// 解析可能带方括号的 IPv6 地址字面量（如 `[::1]`）
fn parse_ip(ip: &str) -> Option<std::net::IpAddr> {
    let trimmed = ip.trim();
    let candidate = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    candidate.parse().ok()
}

/// 构造 PROXY protocol 头
///
/// - `src_ip` / `src_port`：真实访问者地址（来自 `StartWorkConn`）；
/// - `dst_ip` / `dst_port`：本地服务地址；
/// - `version`：`"v1"` → 文本 v1；其余（含 `"v2"`）→ 二进制 v2（对齐原版缺省 v2）。
///
/// 源地址不是合法 IP 字面量（域名等）时输出 UNKNOWN / LOCAL 帧；
/// 目标地址无法解析时以 `0.0.0.0` 占位（仅影响头内目标字段，不影响转发）。
pub fn build_proxy_protocol_header(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    version: &str,
) -> Vec<u8> {
    match parse_ip(src_ip) {
        Some(src) => {
            // 原版语义：version == "v1" 用 v1，其余一律 v2
            if version.eq_ignore_ascii_case("v1") {
                build_v1(src, src_port, parse_ip(dst_ip), dst_port)
            } else {
                build_v2(src, src_port, parse_ip(dst_ip), dst_port)
            }
        }
        None => unknown_header(version),
    }
}

/// v1 文本头
fn build_v1(
    src: std::net::IpAddr,
    src_port: u16,
    dst: Option<std::net::IpAddr>,
    dst_port: u16,
) -> Vec<u8> {
    let proto = match src {
        std::net::IpAddr::V4(_) => "TCP4",
        std::net::IpAddr::V6(_) => "TCP6",
    };
    // 目标地址解析失败时以 0.0.0.0 占位（保持 v1 四元组结构）
    let dst_text = dst
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    // v1 文本不带方括号（规范要求 TCP6 直接写 IPv6 字面量）
    format!("PROXY {proto} {src} {dst_text} {src_port} {dst_port}\r\n").into_bytes()
}

/// v2 二进制头
fn build_v2(
    src: std::net::IpAddr,
    src_port: u16,
    dst: Option<std::net::IpAddr>,
    dst_port: u16,
) -> Vec<u8> {
    let fallback: std::net::IpAddr = "0.0.0.0".parse().expect("valid ip");
    let dst = dst.unwrap_or(fallback);

    let (family, src_octets, dst_octets): (u8, Vec<u8>, Vec<u8>) = match (src, dst) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            (V2_FAMILY_INET, s.octets().to_vec(), d.octets().to_vec())
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            (V2_FAMILY_INET6, s.octets().to_vec(), d.octets().to_vec())
        }
        // 地址族不一致（如 v4 源 + v6 目标）：规范未定义混用，回退 UNKNOWN 语义
        _ => return local_v2_header(),
    };

    let mut payload = Vec::with_capacity(src_octets.len() + dst_octets.len() + 4);
    payload.extend_from_slice(&src_octets);
    payload.extend_from_slice(&dst_octets);
    payload.extend_from_slice(&src_port.to_be_bytes());
    payload.extend_from_slice(&dst_port.to_be_bytes());

    let mut out = Vec::with_capacity(V2_SIGNATURE.len() + 4 + payload.len());
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(V2_VERSION | V2_CMD_PROXY);
    out.push(family | V2_PROTO_STREAM);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// 连接信息不可用：v1 → `PROXY UNKNOWN\r\n`；v2 → LOCAL 命令空帧
fn unknown_header(version: &str) -> Vec<u8> {
    if version.eq_ignore_ascii_case("v1") {
        b"PROXY UNKNOWN\r\n".to_vec()
    } else {
        local_v2_header()
    }
}

/// v2 LOCAL 命令帧（ver=2, cmd=LOCAL, 地址段长度 0）
fn local_v2_header() -> Vec<u8> {
    let mut out = Vec::with_capacity(V2_SIGNATURE.len() + 4);
    out.extend_from_slice(&V2_SIGNATURE);
    out.push(V2_VERSION | V2_CMD_LOCAL);
    out.push(0x00);
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1 IPv4：标准四元组文本
    #[test]
    fn v1_ipv4_exact_bytes() {
        let header = build_proxy_protocol_header("203.0.113.7", 41321, "127.0.0.1", 8080, "v1");
        assert_eq!(
            String::from_utf8(header).unwrap(),
            "PROXY TCP4 203.0.113.7 127.0.0.1 41321 8080\r\n"
        );
    }

    /// v1 IPv6：无方括号字面量 + TCP6
    #[test]
    fn v1_ipv6_without_brackets() {
        let header = build_proxy_protocol_header("[2001:db8::1]", 443, "::1", 80, "v1");
        assert_eq!(
            String::from_utf8(header).unwrap(),
            "PROXY TCP6 2001:db8::1 ::1 443 80\r\n"
        );
    }

    /// v2 IPv4：签名 + ver/cmd/fam/proto/len + 12 字节地址载荷
    #[test]
    fn v2_ipv4_exact_bytes() {
        let header = build_proxy_protocol_header("203.0.113.7", 41321, "127.0.0.1", 8080, "v2");
        let mut expected = V2_SIGNATURE.to_vec();
        expected.push(0x21); // ver 2 | cmd PROXY
        expected.push(0x11); // INET | STREAM
        expected.extend_from_slice(&12u16.to_be_bytes());
        expected.extend_from_slice(&[203, 0, 113, 7]); // src
        expected.extend_from_slice(&[127, 0, 0, 1]); // dst
        expected.extend_from_slice(&41321u16.to_be_bytes());
        expected.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(header, expected);
    }

    /// v2 IPv6：fam=INET6，载荷 36 字节
    #[test]
    fn v2_ipv6_exact_bytes() {
        let header = build_proxy_protocol_header("2001:db8::1", 443, "::1", 80, "v2");
        assert_eq!(header[..12], V2_SIGNATURE);
        assert_eq!(header[12], 0x21);
        assert_eq!(header[13], 0x21); // INET6 | STREAM
        assert_eq!(&header[14..16], &36u16.to_be_bytes());
        assert_eq!(header.len(), 16 + 36);
    }

    /// 原版语义：非 "v1"（含空串）一律走 v2
    #[test]
    fn non_v1_defaults_to_v2() {
        for version in ["v2", "", "V2", "weird"] {
            let header = build_proxy_protocol_header("10.0.0.1", 1, "10.0.0.2", 2, version);
            assert_eq!(header[12] & 0xF0, V2_VERSION, "version={version:?}");
        }
    }

    /// 源地址不可解析：v1 → PROXY UNKNOWN；v2 → LOCAL 空帧
    #[test]
    fn unparseable_src_falls_back() {
        let v1 = build_proxy_protocol_header("visitor.example.com", 1, "127.0.0.1", 80, "v1");
        assert_eq!(v1, b"PROXY UNKNOWN\r\n");

        let v2 = build_proxy_protocol_header("visitor.example.com", 1, "127.0.0.1", 80, "v2");
        assert_eq!(v2[..12], V2_SIGNATURE);
        assert_eq!(v2[12], V2_VERSION | V2_CMD_LOCAL);
        assert_eq!(v2[13], 0x00);
        assert_eq!(&v2[14..16], &[0, 0]);
        assert_eq!(v2.len(), 16);
    }

    /// 目标地址不可解析：v2 以 0.0.0.0 占位且帧结构完整
    #[test]
    fn unparseable_dst_uses_zero_addr() {
        let header = build_proxy_protocol_header("10.0.0.1", 5, "backend.local", 80, "v2");
        assert_eq!(header[13], 0x11);
        assert_eq!(&header[16..20], &[10, 0, 0, 1]);
        assert_eq!(&header[20..24], &[0, 0, 0, 0]);
        assert_eq!(&header[24..26], &5u16.to_be_bytes());
        assert_eq!(&header[26..28], &80u16.to_be_bytes());
    }

    /// v1 目标不可解析：以 0.0.0.0 占位
    #[test]
    fn unparseable_dst_v1_zero_addr() {
        let header = build_proxy_protocol_header("10.0.0.1", 5, "backend.local", 80, "v1");
        assert_eq!(
            String::from_utf8(header).unwrap(),
            "PROXY TCP4 10.0.0.1 0.0.0.0 5 80\r\n"
        );
    }
}
