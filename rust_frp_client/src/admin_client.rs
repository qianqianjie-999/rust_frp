//! frpc 管理 API 的极简 HTTP/1.1 客户端
//!
//! `frpc reload` / `frpc status` 子命令用来与本进程（或远端）frpc 的
//! webServer 管理端口通信。管理端是纯 HTTP（无 TLS），请求体恒为空，
//! 因此不需要引入完整的 HTTP 客户端依赖——用 tokio TcpStream 拼一个
//! 最小请求 + 解析最小响应即可，避免为两个子命令引入 reqwest 这类
//! 重依赖（该 crate 会拖入整套 TLS/压缩栈）。
//!
//! 支持：Content-Length 与 chunked 两种响应体、Basic 认证头。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 向 frpc 管理端口发起一次 HTTP 请求，返回 (状态码, 响应体)。
///
/// `basic_auth` 为 `Some((user, pass))` 时附带 `Authorization: Basic` 头
/// （服务端配置了 `webServer.user`/`password` 时必须提供）。
pub async fn admin_http_request(
    addr: &str,
    port: u16,
    method: &str,
    path: &str,
    basic_auth: Option<(&str, &str)>,
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = tokio::net::TcpStream::connect((addr, port)).await?;

    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {addr}:{port}\r\nConnection: close\r\n");
    if let Some((user, pass)) = basic_auth {
        let encoded = base64::encode(format!("{user}:{pass}"));
        req.push_str(&format!("Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_http_response(&raw)
}

/// 解析 HTTP/1.1 响应字节流，返回 (状态码, 响应体字符串)。
///
/// 响应体长度判定顺序：Content-Length > chunked > 读到 EOF。
fn parse_http_response(
    raw: &[u8],
) -> Result<(u16, String), Box<dyn std::error::Error + Send + Sync>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid HTTP response: header terminator not found")?;
    let head = String::from_utf8_lossy(&raw[..header_end]);

    let status_line = head
        .lines()
        .next()
        .ok_or("invalid HTTP response: empty status line")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("invalid HTTP status line: {status_line}"))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
    }

    let body_bytes = &raw[header_end + 4..];
    let mut body_vec;
    let body: &[u8] = if chunked {
        body_vec = Vec::new();
        decode_chunked_into(body_bytes, &mut body_vec);
        &body_vec
    } else if let Some(len) = content_length {
        &body_bytes[..len.min(body_bytes.len())]
    } else {
        body_bytes
    };

    Ok((status, String::from_utf8_lossy(body).into_owned()))
}

/// chunked 解码（写入调用方缓冲，避免借用问题）。
fn decode_chunked_into(raw: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0;
    while pos < raw.len() {
        let Some(line_end) = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p)
        else {
            break;
        };
        let size_str = String::from_utf8_lossy(&raw[pos..line_end]);
        let size = match usize::from_str_radix(size_str.trim().split(';').next().unwrap_or(""), 16)
        {
            Ok(s) => s,
            Err(_) => break,
        };
        if size == 0 {
            break;
        }
        let data_start = line_end + 2;
        let data_end = (data_start + size).min(raw.len());
        out.extend_from_slice(&raw[data_start..data_end]);
        pos = data_end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"msg\":\"ok\"}";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"msg\":\"ok\"}");
    }

    #[test]
    fn test_parse_response_chunked() {
        let mut raw = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        raw.push_str("5\r\nhello\r\n");
        raw.push_str("6\r\n world\r\n");
        raw.push_str("0\r\n\r\n");
        let (status, body) = parse_http_response(raw.as_bytes()).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "hello world");
    }

    #[test]
    fn test_parse_response_error_status() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 401);
        assert!(body.is_empty());
    }

    #[test]
    fn test_parse_response_missing_terminator_errors() {
        let raw = b"HTTP/1.1 200 OK\r\nno terminator";
        assert!(parse_http_response(raw).is_err());
    }

    #[tokio::test]
    async fn test_admin_http_request_roundtrip() {
        // 起一个一次性 TCP 服务端，回固定响应，验证端到端请求构造与解析
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // 校验 CLI 客户端构造的请求行与 Basic 头
            assert!(req.starts_with("POST /reload HTTP/1.1\r\n"));
            assert!(req.contains("Host:"));
            assert!(req.contains("Authorization: Basic dXNlcjpwYXNz")); // user:pass
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                .await
                .unwrap();
        });

        let (status, body) =
            admin_http_request("127.0.0.1", port, "POST", "/reload", Some(("user", "pass")))
                .await
                .unwrap();
        server.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "done");
    }
}
