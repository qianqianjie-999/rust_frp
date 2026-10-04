//! HTTP 反向代理桥接插件（`http2http` / `http2https`）
//!
//! 对齐原版 frp `pkg/plugin/client/http2http.go` / `http2https.go` 的语义：
//!
//! | 插件 | 访客接入（frpc 侧） | 转发到本地服务 |
//! |------|--------------------|----------------|
//! | `http2http`  | 明文 HTTP  | 明文 HTTP  |
//! | `http2https` | 明文 HTTP  | TLS(HTTPS)，跳过证书校验 |
//!
//! 与 frps 内置 vhost HTTP 转发（纯 TCP 透传，不改写任何头部）的区别在于：
//! 本插件解析 HTTP 报文后**重新发起**请求，因此可以
//!
//! - `hostHeaderRewrite` 改写转发到本地服务的 `Host`（本地服务常按 Host 做虚拟主机路由）；
//! - `requestHeaders.set` 注入/覆盖任意请求头；
//! - 把原本指向 HTTP 的代理改指向 HTTPS 本地服务（`http2https`）。
//!
//! 实现说明与限制：
//! - 支持 `Content-Length` 与 `chunked` 两种请求/响应体分帧，以及 close-delimited 响应；
//! - 到本地服务的连接按「每请求一条」建立并携带 `Connection: close`
//!   （不做上游连接池复用，与本项目零重依赖的取舍一致）；
//! - 支持在同一访客连接上处理多次 keep-alive 请求，直到对端要求关闭或出现 close-delimited 响应。

use crate::{invalid_input, AsyncStream, Plugin};
use rust_frp_config::PluginConfig;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 头部最大字节数（防止对端无界发送导致内存膨胀）
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// 单次读写缓冲
const IO_CHUNK: usize = 8 * 1024;

/// 报文体分帧方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    /// 无报文体
    None,
    /// 固定长度（`Content-Length`）
    Length(u64),
    /// 分块传输（`Transfer-Encoding: chunked`）
    Chunked,
    /// 读到连接关闭为止（仅响应侧可能）
    UntilEof,
}

/// HTTP 反向代理桥接插件
pub struct HttpBridgePlugin {
    local_addr: String,
    host_header_rewrite: Option<String>,
    request_headers: HashMap<String, String>,
    /// 转发到本地服务时使用的 TLS 客户端配置（`None` = 明文 HTTP）
    tls: Option<rust_frp_net::TlsConfig>,
}

impl HttpBridgePlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let local_addr = config.local_addr.clone().ok_or_else(|| {
            invalid_input("local_addr is required for http2http/http2https plugin")
        })?;
        let use_tls = config.r#type == "http2https";
        let request_headers = config
            .request_headers
            .as_ref()
            .map(|h| h.set.clone())
            .unwrap_or_default();
        // 本地服务通常使用自签证书：仅加密不验证（与原版 InsecureSkipVerify 一致）
        let tls = if use_tls {
            Some(rust_frp_net::TlsConfig::new_client_insecure()?)
        } else {
            None
        };
        Ok(Self {
            local_addr,
            host_header_rewrite: config.host_header_rewrite.clone(),
            request_headers,
            tls,
        })
    }

    /// 建立到本地服务的连接（按需叠加 TLS）
    async fn connect_local(
        &self,
    ) -> Result<Box<dyn AsyncStream>, Box<dyn std::error::Error + Send + Sync>> {
        let tcp = tokio::net::TcpStream::connect(&self.local_addr).await?;
        match &self.tls {
            Some(tls) => {
                let domain = host_part(&self.local_addr);
                let stream = tls.connect_stream(&domain, tcp).await?;
                Ok(Box::new(stream) as Box<dyn AsyncStream>)
            }
            None => Ok(Box::new(tcp) as Box<dyn AsyncStream>),
        }
    }
}

#[async_trait::async_trait]
impl Plugin for HttpBridgePlugin {
    async fn handle(
        &mut self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client_pending: Vec<u8> = Vec::new();

        loop {
            // ---- 1. 读取访客请求头 ----
            let Some(head_bytes) = read_head(&mut conn, &mut client_pending).await? else {
                // 对端在发送任何数据前关闭
                return Ok(());
            };
            let request = Request::parse(&head_bytes)?;
            let request_keep_alive = request.keep_alive();
            let request_framing = request.body_framing();

            // ---- 2. 连接本地服务并转发重写后的请求 ----
            let mut local = self.connect_local().await?;
            let out_head = build_forward_request_head(
                &request,
                self.host_header_rewrite.as_deref(),
                &self.request_headers,
                host_part(&self.local_addr),
            );
            local.write_all(out_head.as_bytes()).await?;

            match request_framing {
                BodyFraming::None => {}
                BodyFraming::Length(n) => {
                    copy_exactly(&mut conn, &mut client_pending, &mut local, n).await?;
                }
                BodyFraming::Chunked => {
                    forward_chunked(&mut conn, &mut client_pending, &mut local).await?;
                }
                BodyFraming::UntilEof => {
                    // HTTP/1.1 请求体不会以「连接关闭」定界；防御性处理
                    return Err(invalid_input("unexpected close-delimited request body"));
                }
            }
            local.flush().await?;

            // ---- 3. 读取本地响应并回写 ----
            let mut local_pending: Vec<u8> = Vec::new();
            let Some(resp_bytes) = read_head(&mut local, &mut local_pending).await? else {
                // 本地服务未响应即关闭：直接断开访客连接
                let _ = conn.shutdown().await;
                return Ok(());
            };
            let response = Response::parse(&resp_bytes)?;
            let resp_framing = response.body_framing(&request.method);

            // close-delimited 响应只能靠关闭连接定界，必须结束本次会话。
            // 注意：上游（本地服务）的 `Connection: close` 只描述本地这一跳，
            // 已在回写头部时被剥离，不应作为关闭访客连接的理由。
            let must_close = resp_framing == BodyFraming::UntilEof || !request_keep_alive;
            let out_resp_head = build_forward_response_head(&response, !must_close);
            conn.write_all(out_resp_head.as_bytes()).await?;
            conn.flush().await?;

            match resp_framing {
                BodyFraming::None => {}
                BodyFraming::Length(n) => {
                    copy_exactly(&mut local, &mut local_pending, &mut conn, n).await?;
                }
                BodyFraming::Chunked => {
                    forward_chunked(&mut local, &mut local_pending, &mut conn).await?;
                }
                BodyFraming::UntilEof => {
                    copy_until_eof(&mut local, &mut local_pending, &mut conn).await?;
                }
            }
            conn.flush().await?;
            // 到本地服务的连接按请求建立，处理完即关闭
            let _ = local.shutdown().await;

            if must_close {
                let _ = conn.shutdown().await;
                return Ok(());
            }
        }
    }
}

/// 访客请求（仅解析桥接所需字段）
struct Request {
    method: String,
    target: String,
    /// 是否为 HTTP/1.0（决定缺省连接语义）
    http10: bool,
    headers: Vec<(String, String)>,
}

impl Request {
    fn parse(head: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (first_line, headers) = parse_head(head)?;
        let mut parts = first_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| invalid_input("invalid HTTP request line"))?
            .to_string();
        let target = parts
            .next()
            .ok_or_else(|| invalid_input("invalid HTTP request line"))?
            .to_string();
        // 版本段缺失时按 HTTP/1.1 处理（长连接语义）
        let http10 = parts.next().is_some_and(|v| v.starts_with("HTTP/1.0"));
        Ok(Self {
            method,
            target,
            http10,
            headers,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// HTTP/1.0 默认短连接（除非显式 `Connection: keep-alive`）；HTTP/1.1 默认长连接
    fn keep_alive(&self) -> bool {
        match self.header("connection") {
            Some(v) if v.eq_ignore_ascii_case("close") => false,
            Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
            _ => !self.http10,
        }
    }

    fn body_framing(&self) -> BodyFraming {
        if has_chunked(&self.headers) {
            return BodyFraming::Chunked;
        }
        if let Some(n) = content_length(&self.headers) {
            return BodyFraming::Length(n);
        }
        BodyFraming::None
    }
}

/// 本地响应（仅解析桥接所需字段）
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    fn parse(head: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (first_line, headers) = parse_head(head)?;
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| invalid_input("invalid HTTP status line"))?;
        Ok(Self { status, headers })
    }

    fn body_framing(&self, request_method: &str) -> BodyFraming {
        // 1xx / 204 / 304 与 HEAD 响应无报文体
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return BodyFraming::None;
        }
        if has_chunked(&self.headers) {
            return BodyFraming::Chunked;
        }
        if let Some(n) = content_length(&self.headers) {
            return BodyFraming::Length(n);
        }
        BodyFraming::UntilEof
    }
}

/// 解析后的头部：(首行, 头部键值列表)
type ParsedHead = (String, Vec<(String, String)>);

/// 解析头部为 (首行, 头部列表)
fn parse_head(head: &[u8]) -> Result<ParsedHead, Box<dyn std::error::Error + Send + Sync>> {
    let text = std::str::from_utf8(head)
        .map_err(|_| invalid_input("HTTP header is not valid UTF-8/ASCII"))?;
    let mut lines = text.split("\r\n");
    let first_line = lines
        .next()
        .ok_or_else(|| invalid_input("empty HTTP header"))?
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((first_line, headers))
}

fn has_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    })
}

fn content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok())
}

/// 取 `host:port` 中的 host 部分（TLS SNI 与缺省 Host 头使用）
fn host_part(addr: &str) -> String {
    match addr.rsplit_once(':') {
        Some((host, _)) if !host.is_empty() => {
            // IPv6 字面量形如 [::1]:8080
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        }
        _ => "localhost".to_string(),
    }
}

/// 构造转发到本地服务的请求头
///
/// - 丢弃 `Connection` / `Proxy-Connection`：连接语义由本插件决定
/// - `Host` 按 `hostHeaderRewrite` 改写（未配置则保留访客原值）
/// - `requestHeaders.set` 注入/覆盖（大小写不敏感去重）
/// - 对本地服务统一声明 `Connection: close`（不做上游连接复用）
fn build_forward_request_head(
    request: &Request,
    host_rewrite: Option<&str>,
    extra: &HashMap<String, String>,
    default_host: String,
) -> String {
    let mut headers: Vec<(String, String)> = Vec::new();
    for (k, v) in &request.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "connection" || lower == "proxy-connection" {
            continue;
        }
        if lower == "host" {
            headers.push(("Host".to_string(), host_rewrite.unwrap_or(v).to_string()));
            continue;
        }
        headers.push((k.clone(), v.clone()));
    }
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        headers.push((
            "Host".to_string(),
            host_rewrite.map(str::to_string).unwrap_or(default_host),
        ));
    }
    for (k, v) in extra {
        headers.retain(|(hk, _)| !hk.eq_ignore_ascii_case(k));
        headers.push((k.clone(), v.clone()));
    }
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
    headers.push(("Connection".to_string(), "close".to_string()));

    let mut out = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out
}

/// 构造回写给访客的响应头
///
/// 丢弃上游 `Connection`（本地连接恒为 close，不应透传给访客），
/// 按本插件与访客之间的实际连接语义重新声明。
fn build_forward_response_head(response: &Response, keep_alive: bool) -> String {
    let mut out = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        status_text(response.status)
    );
    for (k, v) in &response.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "connection" || lower == "proxy-connection" || lower == "keep-alive" {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    out.push_str("\r\n");
    out
}

/// 常见状态码的 reason phrase（未知状态码回退为空串，HTTP/1.1 允许）
fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// 读取完整头部（含结尾 `\r\n\r\n`）
///
/// 返回 `Ok(None)` 表示对端在发送任何数据前关闭（正常结束，不算错误）。
async fn read_head(
    conn: &mut Box<dyn AsyncStream>,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(pos) = find_head_end(pending) {
            let head: Vec<u8> = pending.drain(..pos + 4).collect();
            return Ok(Some(head));
        }
        if pending.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP header too large",
            ));
        }
        let mut buf = [0u8; IO_CHUNK];
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            if pending.is_empty() {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed in the middle of HTTP header",
            ));
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 读取一行（含行尾 `\n`）
async fn read_line(
    conn: &mut Box<dyn AsyncStream>,
    pending: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    loop {
        if let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            return Ok(pending.drain(..pos + 1).collect());
        }
        if pending.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "protocol line too long",
            ));
        }
        let mut buf = [0u8; IO_CHUNK];
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed while reading line",
            ));
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// 精确转发 `n` 字节（先消费已缓冲数据）
async fn copy_exactly(
    from: &mut Box<dyn AsyncStream>,
    pending: &mut Vec<u8>,
    to: &mut Box<dyn AsyncStream>,
    mut n: u64,
) -> std::io::Result<()> {
    while n > 0 {
        if !pending.is_empty() {
            let take = std::cmp::min(n as usize, pending.len());
            let chunk: Vec<u8> = pending.drain(..take).collect();
            to.write_all(&chunk).await?;
            n -= take as u64;
            continue;
        }
        let mut buf = [0u8; IO_CHUNK];
        let want = std::cmp::min(n as usize, buf.len());
        let read = from.read(&mut buf[..want]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed while reading fixed-length body",
            ));
        }
        to.write_all(&buf[..read]).await?;
        n -= read as u64;
    }
    Ok(())
}

/// 原样转发 chunked 报文体（含块大小行、块尾 CRLF 与尾部头），直至 0 长度块
async fn forward_chunked(
    from: &mut Box<dyn AsyncStream>,
    pending: &mut Vec<u8>,
    to: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    loop {
        let size_line = read_line(from, pending).await?;
        to.write_all(&size_line).await?;
        let size_text = String::from_utf8_lossy(&size_line);
        let size_field = size_text.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_field, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size")
        })?;
        if size == 0 {
            // 尾部：转发所有 trailer 直到空行
            loop {
                let line = read_line(from, pending).await?;
                let done = line == b"\r\n" || line == b"\n";
                to.write_all(&line).await?;
                if done {
                    return Ok(());
                }
            }
        }
        copy_exactly(from, pending, to, size as u64).await?;
        // 块尾 CRLF
        let crlf = read_line(from, pending).await?;
        to.write_all(&crlf).await?;
    }
}

/// 读到 EOF 为止（close-delimited 响应体）
async fn copy_until_eof(
    from: &mut Box<dyn AsyncStream>,
    pending: &mut Vec<u8>,
    to: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    if !pending.is_empty() {
        let chunk: Vec<u8> = std::mem::take(pending);
        to.write_all(&chunk).await?;
    }
    let mut buf = [0u8; IO_CHUNK];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_request(head: &str) -> Request {
        Request::parse(head.as_bytes()).expect("parse request")
    }

    #[test]
    fn test_request_parse_and_framing() {
        let req = build_request(
            "POST /api/v1?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n",
        );
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/api/v1?x=1");
        assert_eq!(req.body_framing(), BodyFraming::Length(5));
        assert!(req.keep_alive());

        let chunked =
            build_request("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(chunked.body_framing(), BodyFraming::Chunked);

        let bodyless = build_request("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(bodyless.body_framing(), BodyFraming::None);
    }

    #[test]
    fn test_http10_defaults_to_close() {
        let req = build_request("GET / HTTP/1.0\r\nHost: a\r\n\r\n");
        assert!(!req.keep_alive());
        let req = build_request("GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n");
        assert!(req.keep_alive());
        let req = build_request("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert!(!req.keep_alive());
    }

    #[test]
    fn test_forward_head_rewrites_host_and_injects_headers() {
        let req = build_request(
            "GET /index.html HTTP/1.1\r\nHost: web.example.com\r\nUser-Agent: curl\r\n\
             Connection: keep-alive\r\n\r\n",
        );
        let mut extra = HashMap::new();
        extra.insert("X-From-Where".to_string(), "frp".to_string());
        // 覆盖一个已存在头（大小写不敏感）
        extra.insert("user-agent".to_string(), "rust_frp".to_string());

        let out =
            build_forward_request_head(&req, Some("127.0.0.1"), &extra, "localhost".to_string());
        assert!(out.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(out.contains("Host: 127.0.0.1\r\n"));
        assert!(out.contains("X-From-Where: frp\r\n"));
        assert!(out.contains("user-agent: rust_frp\r\n"));
        // 原有的 User-Agent 应被覆盖而非重复
        assert_eq!(out.matches("User-Agent").count(), 0);
        assert_eq!(out.matches("user-agent").count(), 1);
        // 连接语义由插件决定
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.contains("keep-alive"));
    }

    #[test]
    fn test_forward_head_keeps_host_without_rewrite() {
        let req = build_request("GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n");
        let out = build_forward_request_head(&req, None, &HashMap::new(), "localhost".into());
        assert!(out.contains("Host: web.example.com\r\n"));
    }

    #[test]
    fn test_forward_head_adds_host_when_missing() {
        // HTTP/1.0 请求可能没有 Host 头，必须补齐（HTTP/1.1 强制）
        let req = build_request("GET / HTTP/1.0\r\n\r\n");
        let out = build_forward_request_head(&req, None, &HashMap::new(), "127.0.0.1".into());
        assert!(out.contains("Host: 127.0.0.1\r\n"));
        // 内部标记不外发
        assert!(!out.contains("x-frp-proto"));
    }

    #[test]
    fn test_response_body_framing() {
        let ok = Response::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
        assert_eq!(ok.body_framing("GET"), BodyFraming::Length(3));

        let chunked =
            Response::parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(chunked.body_framing("GET"), BodyFraming::Chunked);

        let close_delimited = Response::parse(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n").unwrap();
        assert_eq!(close_delimited.body_framing("GET"), BodyFraming::UntilEof);

        // HEAD / 204 / 304 无报文体
        let no_body = Response::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
        assert_eq!(no_body.body_framing("HEAD"), BodyFraming::None);
        let not_modified = Response::parse(b"HTTP/1.1 304 Not Modified\r\n\r\n").unwrap();
        assert_eq!(not_modified.body_framing("GET"), BodyFraming::None);
    }

    #[test]
    fn test_forward_response_head_strips_upstream_connection() {
        let resp = Response::parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\nKeep-Alive: timeout=5\r\n\r\n",
        )
        .unwrap();
        let keep = build_forward_response_head(&resp, true);
        assert!(keep.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(keep.contains("Content-Length: 3\r\n"));
        assert!(keep.contains("Connection: keep-alive\r\n"));
        assert!(!keep.contains("Keep-Alive:"));
        assert_eq!(keep.matches("Connection:").count(), 1);

        let close = build_forward_response_head(&resp, false);
        assert!(close.contains("Connection: close\r\n"));
    }

    #[test]
    fn test_plugin_requires_local_addr() {
        let cfg = PluginConfig {
            r#type: "http2http".to_string(),
            ..Default::default()
        };
        assert!(HttpBridgePlugin::new(&cfg).is_err());
    }

    #[test]
    fn test_plugin_scheme_follows_type() {
        let mut cfg = PluginConfig {
            r#type: "http2http".to_string(),
            local_addr: Some("127.0.0.1:80".to_string()),
            ..Default::default()
        };
        // http2http：明文转发（无 TLS 客户端配置）
        assert!(HttpBridgePlugin::new(&cfg).unwrap().tls.is_none());
        // http2https：叠加 TLS 客户端
        cfg.r#type = "http2https".to_string();
        assert!(HttpBridgePlugin::new(&cfg).unwrap().tls.is_some());
    }

    #[test]
    fn test_host_part_variants() {
        assert_eq!(host_part("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(host_part("[::1]:8443"), "::1");
        // 无端口分隔或 host 为空时回退 localhost
        assert_eq!(host_part("nohost"), "localhost");
        assert_eq!(host_part(":80"), "localhost");
    }

    /// 端到端：访客请求 → 插件重写 → 本地服务；响应回写访客
    fn fixed_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn test_bridge_rewrites_host_and_injects_header() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let captured_inner = std::sync::Arc::clone(&captured);
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();

        let local_task = tokio::spawn(async move {
            let (mut sock, _) = local.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let received = String::from_utf8_lossy(&buf[..n]).into_owned();
            *captured_inner.lock().unwrap() = received;
            sock.write_all(&fixed_response("hello")).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let visitor = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(
                b"GET /hello?x=1 HTTP/1.1\r\nHost: web.example.com\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut out = Vec::new();
            c.read_to_end(&mut out).await.unwrap();
            String::from_utf8_lossy(&out).into_owned()
        });

        let (sock, _) = listener.accept().await.unwrap();
        let cfg = PluginConfig {
            r#type: "http2http".to_string(),
            local_addr: Some(local_addr.to_string()),
            host_header_rewrite: Some("127.0.0.1".to_string()),
            request_headers: Some(rust_frp_config::HeaderOperations {
                set: HashMap::from([("X-From-Where".to_string(), "frp".to_string())]),
            }),
            ..Default::default()
        };
        let mut plugin = HttpBridgePlugin::new(&cfg).unwrap();
        plugin.handle(Box::new(sock)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), local_task)
            .await
            .expect("local service did not receive the expected requests")
            .unwrap();

        let seen = captured.lock().unwrap().clone();
        assert!(
            seen.starts_with("GET /hello?x=1 HTTP/1.1\r\n"),
            "seen: {seen}"
        );
        assert!(seen.contains("Host: 127.0.0.1\r\n"), "seen: {seen}");
        assert!(seen.contains("X-From-Where: frp\r\n"), "seen: {seen}");
        assert!(seen.contains("Connection: close\r\n"), "seen: {seen}");

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), visitor)
            .await
            .expect("visitor did not receive a response")
            .unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "resp: {response}"
        );
        assert!(response.ends_with("hello"), "resp: {response}");
        assert!(
            response.contains("Connection: close\r\n"),
            "resp: {response}"
        );
    }

    #[tokio::test]
    async fn test_bridge_forwards_chunked_request_body() {
        // 本地服务：读取 chunked 请求体并原样回显为固定长度响应
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        let local_task = tokio::spawn(async move {
            let (mut sock, _) = local.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut total = String::new();
            // 读两次即可覆盖 head + 完整 chunked body
            for _ in 0..2 {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total.push_str(&String::from_utf8_lossy(&buf[..n]));
                if total.contains("0\r\n\r\n") {
                    break;
                }
            }
            let body = if total.contains("hello") {
                "ok"
            } else {
                "miss"
            };
            sock.write_all(&fixed_response(body)).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let visitor = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(
                b"POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
            let mut out = Vec::new();
            c.read_to_end(&mut out).await.unwrap();
            String::from_utf8_lossy(&out).into_owned()
        });

        let (sock, _) = listener.accept().await.unwrap();
        let cfg = PluginConfig {
            r#type: "http2http".to_string(),
            local_addr: Some(local_addr.to_string()),
            ..Default::default()
        };
        let mut plugin = HttpBridgePlugin::new(&cfg).unwrap();
        plugin.handle(Box::new(sock)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), local_task)
            .await
            .expect("local service did not receive the expected requests")
            .unwrap();

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), visitor)
            .await
            .expect("visitor did not receive a response")
            .unwrap();
        assert!(response.ends_with("ok"), "resp: {response}");
    }

    #[tokio::test]
    async fn test_bridge_handles_keep_alive_then_close() {
        // 单一访客连接上串行两个请求，第二个要求关闭
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        let local_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut sock, _) = local.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await.unwrap();
                sock.write_all(&fixed_response("ok")).await.unwrap();
                let _ = sock.shutdown().await;
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let visitor = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            // 第一个请求保持连接
            c.write_all(b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let mut first = String::new();
            // 读满第一个响应（响应体以 "ok" 结尾）
            while !first.ends_with("ok") {
                let n = c.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                first.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            // 第二个请求要求关闭
            c.write_all(b"GET /2 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).await.unwrap();
            (first, String::from_utf8_lossy(&rest).into_owned())
        });

        let (sock, _) = listener.accept().await.unwrap();
        let cfg = PluginConfig {
            r#type: "http2http".to_string(),
            local_addr: Some(local_addr.to_string()),
            ..Default::default()
        };
        let mut plugin = HttpBridgePlugin::new(&cfg).unwrap();
        plugin.handle(Box::new(sock)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), local_task)
            .await
            .expect("local service did not receive the expected requests")
            .unwrap();

        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), visitor)
            .await
            .expect("visitor did not receive responses")
            .unwrap();
        // 第一个响应保持连接（keep-alive），第二个关闭
        assert!(
            first.contains("Connection: keep-alive\r\n"),
            "first: {first}"
        );
        assert!(first.ends_with("ok"), "first: {first}");
        assert!(second.contains("Connection: close\r\n"), "second: {second}");
        assert!(second.ends_with("ok"), "second: {second}");
    }
}
