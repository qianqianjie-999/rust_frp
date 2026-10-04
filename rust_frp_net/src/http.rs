//! 极简 HTTP/1.1 客户端
//!
//! 本模块只覆盖项目内部的少量出站 HTTP 需求，不追求通用性：
//!
//! - OIDC 服务端：拉取 `{issuer}/.well-known/openid-configuration` 与 JWKS
//! - OIDC 客户端：向 token 端点发起 `client_credentials` 请求
//! - 服务端 HTTP 插件：向外部回调地址 POST JSON
//!
//! # 能力边界
//!
//! - 仅 `GET` / `POST`，`Connection: close`（一次请求一条连接，不做 keep-alive）
//! - 支持 `http://`（明文）与 `https://`（经 [`TlsConfig`]，可校验证书或指定 CA）
//! - 解析 `Content-Length` 与 `Transfer-Encoding: chunked` 两种响应体
//! - 整体超时（连接 + 收发），避免回调/IdP 不可达时长时间挂起
//!
//! 不依赖额外的 HTTP 客户端库，避免为一个内部需求引入重量级依赖树。

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{AnyConn, TlsConfig};

/// 单次请求的 TLS 与超时选项
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// 是否校验证书（`false` 时仅加密不认证，对应原版 `insecureSkipVerify`）
    pub tls_verify: bool,
    /// 自定义根 CA 文件（`Some` 时忽略 `tls_verify`，用指定 CA 校验）
    pub ca_file: Option<String>,
    /// 整体超时（连接建立 + 请求发送 + 响应读取）
    pub timeout: Duration,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            tls_verify: true,
            ca_file: None,
            timeout: Duration::from_secs(10),
        }
    }
}

/// HTTP 响应（状态码 + 解码后的响应体）
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// 状态码（如 200、404）
    pub status: u16,
    /// 响应体（UTF-8 有损解码）
    pub body: String,
}

impl HttpResponse {
    /// 状态码是否为 2xx
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// 请求方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// 解析后的 URL
struct ParsedUrl {
    use_tls: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

/// 解析 `http(s)://host[:port][/path][?query]`
///
/// 未带 scheme 时按 `http` 处理（与原版插件 addr 的宽松约定一致）。
fn parse_url(raw: &str) -> Result<ParsedUrl, String> {
    let (use_tls, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (false, r)
    } else {
        (false, raw)
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(format!("invalid url (empty authority): {raw}"));
    }
    let (host, port) = split_host_port(authority, use_tls)?;
    // path 为空 → "/"；直接以 '?' 开头（只有 query）→ "/?xxx"
    let path_and_query = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Ok(ParsedUrl {
        use_tls,
        host,
        port,
        path_and_query,
    })
}

/// 拆分 authority 的 host 与 port，支持 `[::1]:8080` 形式的 IPv6 字面量
fn split_host_port(authority: &str, use_tls: bool) -> Result<(String, u16), String> {
    let default_port = if use_tls { 443 } else { 80 };
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("invalid IPv6 authority: {authority}"))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| format!("invalid port in authority: {authority}"))?,
            None => default_port,
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse()
                .map_err(|_| format!("invalid port in authority: {authority}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

/// 建立到目标的连接（按需 TLS）
async fn connect_to(
    host: &str,
    port: u16,
    use_tls: bool,
    opts: &HttpOptions,
) -> Result<AnyConn, String> {
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("connect {host}:{port} failed: {e}"))?;
    if !use_tls {
        return Ok(Box::new(tcp));
    }
    let tls = if let Some(ca_file) = &opts.ca_file {
        TlsConfig::new_client_with_ca_file(ca_file)
    } else if opts.tls_verify {
        TlsConfig::new_client()
    } else {
        TlsConfig::new_client_insecure()
    }
    .map_err(|e| format!("failed to build TLS client config: {e}"))?;
    let stream = tls
        .connect(host, tcp)
        .await
        .map_err(|e| format!("TLS handshake with {host}:{port} failed: {e}"))?;
    Ok(Box::new(stream))
}

/// 发起一次 HTTP 请求，返回状态码与响应体
///
/// - `content_type`：非空时写入 `Content-Type` 头
/// - `extra_headers`：追加的自定义头（如 `X-Frp-Reqid`）
pub async fn request(
    method: Method,
    url: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    opts: &HttpOptions,
) -> Result<HttpResponse, String> {
    let parsed = parse_url(url)?;
    let host_header =
        if (parsed.use_tls && parsed.port == 443) || (!parsed.use_tls && parsed.port == 80) {
            parsed.host.clone()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
    let body_len = body.map(|b| b.len()).unwrap_or(0);

    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        method.as_str(),
        parsed.path_and_query,
        host_header
    );
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {body_len}\r\nConnection: close\r\n\r\n"
    ));

    let fut = async {
        let mut stream = connect_to(&parsed.host, parsed.port, parsed.use_tls, opts).await?;
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| format!("write request head failed: {e}"))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .await
                .map_err(|e| format!("write request body failed: {e}"))?;
        }
        stream
            .flush()
            .await
            .map_err(|e| format!("flush request failed: {e}"))?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("read response failed: {e}"))?;
        Ok::<Vec<u8>, String>(raw)
    };

    let raw = match tokio::time::timeout(opts.timeout, fut).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(format!(
                "request to {url} timed out after {:?}",
                opts.timeout
            ))
        }
    };
    parse_http_response(&raw)
}

/// 发起 GET 请求
pub async fn get(url: &str, opts: &HttpOptions) -> Result<HttpResponse, String> {
    request(Method::Get, url, None, None, &[], opts).await
}

/// 发起 JSON POST 请求（请求体为 `application/json`）
pub async fn post_json(
    url: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
    opts: &HttpOptions,
) -> Result<HttpResponse, String> {
    request(
        Method::Post,
        url,
        Some("application/json"),
        Some(body),
        extra_headers,
        opts,
    )
    .await
}

/// 发起表单 POST 请求（`application/x-www-form-urlencoded`）
///
/// 用于 OAuth2 `client_credentials` 令牌请求。
pub async fn post_form(
    url: &str,
    params: &[(&str, &str)],
    opts: &HttpOptions,
) -> Result<HttpResponse, String> {
    let body = encode_form(params);
    request(
        Method::Post,
        url,
        Some("application/x-www-form-urlencoded"),
        Some(body.as_bytes()),
        &[],
        opts,
    )
    .await
}

/// `application/x-www-form-urlencoded` 编码（键值均做百分号转义）
fn encode_form(params: &[(&str, &str)]) -> String {
    let mut parts = Vec::with_capacity(params.len());
    for (k, v) in params {
        parts.push(format!("{}={}", percent_encode(k), percent_encode(v)));
    }
    parts.join("&")
}

/// 百分号转义：非 `unreserved`（ALPHA / DIGIT / `-` `.` `_` `~`）字节转 `%XX`，
/// 空格编码为 `+`（form-urlencoded 约定）
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解析 HTTP/1.1 响应，返回状态码与响应体
///
/// 不要求 2xx：调用方自行判断状态码（OIDC 错误响应体里带诊断信息）。
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid response: header terminator not found")?;
    let head = String::from_utf8_lossy(&raw[..header_end]);

    let status_line = head
        .lines()
        .next()
        .ok_or("invalid response: empty status line")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("invalid status line: {status_line}"))?;

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

    Ok(HttpResponse {
        status,
        body: String::from_utf8_lossy(body).into_owned(),
    })
}

/// chunked 解码（写入调用方缓冲，避免借用问题）
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
    fn test_parse_url_variants() {
        let u = parse_url("http://127.0.0.1:9000/handler").unwrap();
        assert!(!u.use_tls);
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 9000);
        assert_eq!(u.path_and_query, "/handler");

        // 无 scheme + 无端口 → http 默认 80
        let u = parse_url("example.com/plugin").unwrap();
        assert!(!u.use_tls);
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path_and_query, "/plugin");

        // https 默认 443
        let u = parse_url("https://idp.example.com").unwrap();
        assert!(u.use_tls);
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/");

        // 只有 query
        let u = parse_url("http://h:8080?op=Login").unwrap();
        assert_eq!(u.path_and_query, "/?op=Login");
        assert_eq!(u.port, 8080);

        // IPv6 字面量
        let u = parse_url("http://[::1]:7000/x").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 7000);

        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://h:notaport/x").is_err());
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("abc-._~XYZ019"), "abc-._~XYZ019");
        assert_eq!(percent_encode("a b"), "a+b");
        assert_eq!(percent_encode("a/b?c=d&e"), "a%2Fb%3Fc%3Dd%26e");
        assert_eq!(
            encode_form(&[("grant_type", "client_credentials"), ("scope", "a b")]),
            "grant_type=client_credentials&scope=a+b"
        );
    }

    #[test]
    fn test_parse_http_response_content_length_and_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloextra";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "hello");
        assert!(r.is_success());

        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno!";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, "no!");
        assert!(!r.is_success());

        // chunked：5 字节 + 3 字节 + 结束块
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let r = parse_http_response(raw).unwrap();
        assert_eq!(r.body, "helloabc");

        assert!(parse_http_response(b"garbage").is_err());
    }

    /// 起一个一次性 HTTP 服务端：读取请求头 + Content-Length 指定的请求体，
    /// 回写固定响应；返回 (端口, 收到请求原文句柄)。
    async fn spawn_http(
        status_line: &'static str,
        resp_body: &'static str,
        extra_headers: &'static str,
    ) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = sock.read(&mut buf).await.unwrap();
            let head_end = buf[..n].windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let content_length: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    (k.trim().eq_ignore_ascii_case("content-length"))
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            let body_start = head_end + 4;
            // 简单起见，测试请求体不会超过读缓冲
            let req = String::from_utf8_lossy(&buf[..body_start + content_length]).to_string();
            let resp = format!(
                "{status_line}\r\n{extra_headers}Content-Length: {}\r\n\r\n{resp_body}",
                resp_body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (port, handle)
    }

    #[tokio::test]
    async fn test_get_roundtrip() {
        let (port, handle) = spawn_http("HTTP/1.1 200 OK", "{\"ok\":true}", "").await;
        let opts = HttpOptions {
            timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let resp = get(&format!("http://127.0.0.1:{port}/x"), &opts)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"ok\":true}");
        let req = handle.await.unwrap();
        assert!(req.starts_with("GET /x HTTP/1.1\r\n"));
        assert!(req.contains("Host: 127.0.0.1:"));
        assert!(req.contains("Connection: close"));
    }

    #[tokio::test]
    async fn test_post_form_sends_encoded_body_and_headers() {
        let (port, handle) = spawn_http("HTTP/1.1 200 OK", "token", "").await;
        let opts = HttpOptions::default();
        let resp = post_form(
            &format!("http://127.0.0.1:{port}/token"),
            &[("grant_type", "client_credentials"), ("client_id", "a b")],
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(resp.body, "token");
        let req = handle.await.unwrap();
        assert!(req.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(req.contains("Content-Type: application/x-www-form-urlencoded"));
        assert!(req.ends_with("grant_type=client_credentials&client_id=a+b"));
    }

    #[tokio::test]
    async fn test_post_json_and_extra_headers() {
        let (port, handle) = spawn_http("HTTP/1.1 200 OK", "ok", "X-Test: 1\r\n").await;
        let opts = HttpOptions::default();
        let resp = post_json(
            &format!("http://127.0.0.1:{port}/cb"),
            b"{\"a\":1}",
            &[("X-Frp-Reqid", "deadbeef")],
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(resp.body, "ok");
        let req = handle.await.unwrap();
        assert!(req.contains("Content-Type: application/json"));
        assert!(req.contains("X-Frp-Reqid: deadbeef"));
        assert!(req.ends_with("{\"a\":1}"));
    }

    #[tokio::test]
    async fn test_request_timeout() {
        // 服务端接受连接后什么都不回 → 触发超时
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _guard = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let opts = HttpOptions {
            timeout: Duration::from_millis(150),
            ..Default::default()
        };
        let err = get(&format!("http://127.0.0.1:{port}/"), &opts)
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_connect_refused_is_error() {
        // 127.0.0.1:1 基本不会有人监听
        let opts = HttpOptions::default();
        let err = get("http://127.0.0.1:1/", &opts).await.unwrap_err();
        assert!(err.contains("connect"), "unexpected error: {err}");
    }
}
