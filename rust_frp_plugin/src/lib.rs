//! FRP 插件系统模块
//!
//! 该模块实现了 FRP 的插件系统，允许在代理连接上执行自定义处理逻辑。
//!
//! ## 支持的插件类型
//!
//! 1. **UnixDomainSocketPlugin (Unix 域套接字)**
//!    - 将外部连接转发到 Unix 域套接字
//!    - 常用于本地服务暴露
//!
//! 2. **StaticFilePlugin (静态文件)**
//!    - 提供本地文件作为 HTTP 响应
//!    - 支持路径前缀剥离
//!    - 内置路径遍历攻击防护
//!
//! 3. **HttpProxyPlugin (HTTP 代理)**
//!    - 实现 HTTP CONNECT 代理功能
//!    - 支持隧道穿过防火墙
//!
//! 4. **Socks5Plugin (SOCKS5 代理)**
//!    - 实现 SOCKS5 协议
//!    - 支持域名和 IPv4 地址
//!
//! 5. **TlsOffloadPlugin (TLS 卸载,https2http / tls2raw)**
//!    - 访客 TLS 接入 → 终止 TLS → 明文桥接到 local_addr
//!    - 证书:显式 crt_path/key_path 或内置自签名证书
//!
//! 6. **TlsBridgePlugin (https2https)**
//!    - 访客 TLS 接入 → 终止 TLS → 重新 TLS 连接 local_addr(双层 TLS)
//!    - 本地侧跳过证书验证(自签场景)
//!
//! 7. **HttpBridgePlugin (http2http / http2https)**
//!    - 访客明文 HTTP 接入 → 解析并重写请求 → 转发到本地 HTTP / HTTPS 服务
//!    - 支持 hostHeaderRewrite 与 requestHeaders.set 注入
//!
//! ## 架构图
//!
//! ```text
//!                    ┌─────────────────────┐
//!                    │   PluginManager      │
//!                    │  (插件管理器)        │
//!                    └─────────────────────┘
//!                              │
//!              ┌───────────────┼───────────────┐
//!              ▼               ▼               ▼
//!        ┌──────────┐    ┌──────────┐    ┌──────────┐
//!        │  Unix    │    │  Static  │    │  SOCKS5  │
//!        │  Domain  │    │  File    │    │  Proxy   │
//!        │  Socket  │    │          │    │          │
//!        └──────────┘    └──────────┘    └──────────┘
//!              │               │               │
//!              └───────────────┴───────────────┘
//!                              │
//!                              ▼
//!                    ┌─────────────────────┐
//!                    │    Plugin trait      │
//!                    │  handle(conn) -> ()  │
//!                    └─────────────────────┘
//! ```
//!
//! ## 安全性
//!
//! - 静态文件插件防止路径遍历攻击
//! - 使用规范化路径比较
//! - 验证文件在允许目录内
//!
//! ## 使用示例
//!
//! ```toml
//! [[proxies]]
//! name = "unix_sock"
//! type = "tcp"
//! remote_port = 6000
//! [proxies.plugin]
//! type = "unix_domain_socket"
//! unix_path = "/var/run/docker.sock"
//! ```

use async_trait::async_trait;
use rust_frp_config::PluginConfig;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

/// 服务端 HTTP 插件机制（frps 控制面回调），与本地插件（数据面）互补。
pub mod server_plugin;

/// HTTP 反向代理桥接插件（http2http / http2https）
pub mod http_bridge;
pub use http_bridge::HttpBridgePlugin;

/// Combined trait for AsyncRead + AsyncWrite
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for T {}

/// 常量时间字节比较，避免凭据比对出现时序侧信道
fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// 常量时间字符串比较
fn constant_time_eq(a: &str, b: &str) -> bool {
    constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// 根据文件扩展名推断 Content-Type
fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("txt") | Some("log") | Some("md") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

/// 插件接口
#[async_trait]
pub trait Plugin: Send + Sync {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// 插件工厂
pub trait PluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Unix 域套接字插件
pub struct UnixDomainSocketPlugin {
    unix_path: String,
}

impl UnixDomainSocketPlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(unix_path) = &config.unix_path {
            Ok(Self {
                unix_path: unix_path.clone(),
            })
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unix_path is required for unix_domain_socket plugin",
            )))
        }
    }
}

#[async_trait]
impl Plugin for UnixDomainSocketPlugin {
    async fn handle(
        &mut self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 连接到 Unix 域套接字
        let mut unix_conn = UnixStream::connect(&self.unix_path).await?;

        // 双向转发数据
        tokio::io::copy_bidirectional(&mut conn, &mut unix_conn).await?;
        Ok(())
    }
}

/// 静态文件插件
pub struct StaticFilePlugin {
    local_path: String,
    strip_prefix: Option<String>,
    http_user: Option<String>,
    http_password: Option<String>,
}

impl StaticFilePlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(local_path) = &config.local_path {
            Ok(Self {
                local_path: local_path.clone(),
                strip_prefix: config.strip_prefix.clone(),
                http_user: config.http_user.clone(),
                http_password: config.http_password.clone(),
            })
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local_path is required for static_file plugin",
            )))
        }
    }

    /// 处理 HTTP 请求
    async fn handle_http_request(
        &self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取 HTTP 请求
        let mut buf = [0; 1024];
        let n = conn.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        // 解析 HTTP 请求
        let lines: Vec<&str> = request.lines().collect();
        if lines.is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP request",
            )));
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP request line",
            )));
        }

        let method = parts[0];
        let path = parts[1];

        // 配置了 http_user 即强制 Basic 认证；此前 http_user/http_password
        // 只存进结构体从未被读取，静态文件实际是匿名可访问的。
        if !self.check_basic_auth(&lines) {
            let body = "Unauthorized";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\n\
                 WWW-Authenticate: Basic realm=\"frp static file\"\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 处理 GET 请求
        if method == "GET" {
            // 构建文件路径
            let file_path = self.build_file_path(path);
            self.serve_file(&file_path, conn).await?;
        } else {
            // 不支持的方法
            let response = "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nMethod not allowed";
            conn.write_all(response.as_bytes()).await?;
        }

        Ok(())
    }

    /// 校验 HTTP Basic 认证
    ///
    /// 返回 `true` 表示放行：
    /// - 未配置 `http_user`（未启用认证，匿名可访问）
    /// - 或请求头里的凭据与配置匹配（常量时间比较）
    fn check_basic_auth(&self, lines: &[&str]) -> bool {
        let Some(expected_user) = self.http_user.as_deref() else {
            return true;
        };
        let expected_password = self.http_password.as_deref().unwrap_or("");

        let header = lines.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("authorization") {
                Some(value.trim())
            } else {
                None
            }
        });

        let Some(header) = header else {
            return false;
        };
        let Some(encoded) = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        else {
            return false;
        };

        let Ok(decoded) = base64::decode(encoded.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = decoded.split_once(':') else {
            return false;
        };

        let user_ok = constant_time_eq(user, expected_user);
        let password_ok = constant_time_eq(password, expected_password);
        user_ok && password_ok
    }

    /// 构建文件路径
    fn build_file_path(&self, path: &str) -> String {
        let mut file_path = self.local_path.clone();
        let mut request_path = path;

        // 去除查询参数
        if let Some(idx) = path.find('?') {
            request_path = &path[..idx];
        }

        // 去除 strip_prefix
        if let Some(prefix) = &self.strip_prefix {
            if request_path.starts_with(&format!("/{}", prefix)) {
                request_path = &request_path[prefix.len() + 1..];
            }
        }

        // 构建最终文件路径
        if request_path != "/" {
            file_path.push_str(request_path);
        }

        file_path
    }

    /// 提供文件
    async fn serve_file(
        &self,
        file_path: &str,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = Path::new(file_path);

        // 检查路径是否在允许目录内，防止路径遍历攻击
        let canonical_path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        let base_path = Path::new(&self.local_path).canonicalize()?;
        if !canonical_path.starts_with(base_path) {
            // 检测到路径遍历攻击
            let response =
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess forbidden";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 检查文件是否存在
        if !canonical_path.exists() {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 检查是否是文件
        if !canonical_path.is_file() {
            let response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 流式发送文件：不再一次性 read_to_end 到内存，避免大文件顶爆内存
        let metadata = tokio::fs::metadata(&canonical_path).await?;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            content_type_for(&canonical_path),
            metadata.len()
        );
        conn.write_all(response.as_bytes()).await?;

        let mut file = tokio::fs::File::open(&canonical_path).await?;
        tokio::io::copy(&mut file, &mut conn).await?;
        conn.flush().await?;

        Ok(())
    }
}

#[async_trait]
impl Plugin for StaticFilePlugin {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle_http_request(conn).await
    }
}

/// HTTP 代理插件（HTTP CONNECT 隧道）
///
/// 访客按 `CONNECT host:port` 语义建立隧道并双向转发。
/// 配置了 `http_user` / `http_password` 时强制校验 `Proxy-Authorization: Basic`
/// 请求头；校验在解析目标之前进行，未通过一律 407（不暴露代理行为）。
/// 已知限制：仅支持 CONNECT，普通 HTTP 转发未实现（见 README）。
pub struct HttpProxyPlugin {
    http_user: Option<String>,
    http_password: Option<String>,
}

impl HttpProxyPlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            http_user: config.http_user.clone(),
            http_password: config.http_password.clone(),
        })
    }

    /// 校验代理认证（`Proxy-Authorization: Basic`）
    ///
    /// 未配置 `http_user` / `http_password` 时视为匿名代理直接放行；
    /// 配置后必须提供匹配凭据（常量时间比较），否则返回 `false`。
    fn check_proxy_auth(&self, lines: &[&str]) -> bool {
        if self.http_user.is_none() && self.http_password.is_none() {
            return true;
        }
        let expected_user = self.http_user.as_deref().unwrap_or("");
        let expected_password = self.http_password.as_deref().unwrap_or("");

        let header = lines.iter().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("proxy-authorization") {
                Some(value.trim())
            } else {
                None
            }
        });

        let Some(header) = header else {
            return false;
        };
        let Some((scheme, encoded)) = header.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }

        let Ok(decoded) = base64::decode(encoded.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return false;
        };
        let Some((user, password)) = decoded.split_once(':') else {
            return false;
        };

        constant_time_eq(user, expected_user) && constant_time_eq(password, expected_password)
    }

    /// 处理 HTTP 代理请求
    async fn handle_http_proxy_request(
        &self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取 HTTP 请求
        let mut buf = [0; 1024];
        let n = conn.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        // 解析 HTTP 请求
        let lines: Vec<&str> = request.lines().collect();
        if lines.is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP request",
            )));
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP request line",
            )));
        }

        // 认证先于命令分派：未通过认证不解析目标、不暴露代理行为
        if !self.check_proxy_auth(&lines) {
            let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"frp http proxy\"\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        if parts[0] != "CONNECT" {
            // 本实现仅支持 CONNECT 隧道；普通 HTTP 转发（原版支持）尚未实现
            let body = "Method Not Allowed: only CONNECT is supported";
            let response = format!(
                "HTTP/1.1 405 Method Not Allowed\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        let target = parts[1];

        // 连接到目标服务器（TcpStream::connect 支持域名解析，与原版 net.Dial 一致）
        let mut target_conn = match tokio::net::TcpStream::connect(target).await {
            Ok(c) => c,
            Err(_) => {
                let response = "HTTP/1.1 502 Bad Gateway\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 发送 HTTP 响应
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        conn.write_all(response.as_bytes()).await?;

        // 双向转发数据
        tokio::io::copy_bidirectional(&mut conn, &mut target_conn).await?;

        Ok(())
    }
}

#[async_trait]
impl Plugin for HttpProxyPlugin {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle_http_proxy_request(conn).await
    }
}

/// SOCKS5 代理插件
///
/// 支持 `CONNECT` 命令（IPv4 / 域名 / IPv6）。配置了 `username` / `password`
/// 时按 RFC 1929 强制用户名密码认证；未配置时使用「无认证」方法。
pub struct Socks5Plugin {
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Plugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            username: config.username.clone(),
            password: config.password.clone(),
        })
    }

    /// 是否需要用户名密码认证
    fn needs_auth(&self) -> bool {
        self.username.is_some() || self.password.is_some()
    }

    /// 从客户端提供的方法列表中选择一个
    ///
    /// - 需要认证：仅当客户端提供 `0x02`（用户名/密码）时选中，否则 `None`（回 0xFF）
    /// - 无需认证：优先 `0x00`（无认证），客户端未提供时 `None`
    fn select_method(methods: &[u8], need_auth: bool) -> Option<u8> {
        if need_auth {
            methods.contains(&0x02).then_some(0x02)
        } else if methods.contains(&0x00) {
            Some(0x00)
        } else {
            None
        }
    }

    /// 按 RFC 1929 校验用户名/密码（常量时间比较）
    fn verify_credentials(&self, user: &[u8], password: &[u8]) -> bool {
        let expected_user = self.username.as_deref().unwrap_or("");
        let expected_password = self.password.as_deref().unwrap_or("");
        constant_time_eq_bytes(user, expected_user.as_bytes())
            && constant_time_eq_bytes(password, expected_password.as_bytes())
    }

    /// 处理 SOCKS5 代理请求
    async fn handle_socks5_request(
        &self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // ---- 1. 方法协商（RFC 1928） ----
        let mut head = [0u8; 2];
        conn.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(invalid_input("invalid SOCKS5 version"));
        }
        let nmethods = head[1] as usize;
        if nmethods == 0 {
            conn.write_all(&[0x05, 0xFF]).await?;
            return Err(invalid_input("SOCKS5 client offered no auth methods"));
        }
        let mut methods = vec![0u8; nmethods];
        conn.read_exact(&mut methods).await?;

        let Some(method) = Self::select_method(&methods, self.needs_auth()) else {
            conn.write_all(&[0x05, 0xFF]).await?;
            return Err(invalid_input("no acceptable SOCKS5 auth method"));
        };
        conn.write_all(&[0x05, method]).await?;

        // ---- 2. 用户名密码子协商（RFC 1929） ----
        if method == 0x02 {
            let mut auth_ver = [0u8; 1];
            conn.read_exact(&mut auth_ver).await?;
            let mut ulen = [0u8; 1];
            conn.read_exact(&mut ulen).await?;
            let mut user = vec![0u8; ulen[0] as usize];
            conn.read_exact(&mut user).await?;
            let mut plen = [0u8; 1];
            conn.read_exact(&mut plen).await?;
            let mut password = vec![0u8; plen[0] as usize];
            conn.read_exact(&mut password).await?;

            if auth_ver[0] != 0x01 {
                conn.write_all(&[0x01, 0x01]).await?;
                return Err(invalid_input("invalid SOCKS5 auth version"));
            }
            if !self.verify_credentials(&user, &password) {
                // 认证失败：按 RFC 1929 回 status=0x01 后正常结束
                conn.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
            conn.write_all(&[0x01, 0x00]).await?;
        }

        // ---- 3. 请求解析（RFC 1928） ----
        let mut req = [0u8; 4];
        conn.read_exact(&mut req).await?;
        if req[0] != 0x05 {
            return Err(invalid_input("invalid SOCKS5 request version"));
        }
        if req[1] != 0x01 {
            // 仅支持 CONNECT（0x01）；0x07 = Command not supported
            conn.write_all(&socks5_reply(0x07)).await?;
            return Err(invalid_input("unsupported SOCKS5 command (only CONNECT)"));
        }

        let target = match req[3] {
            0x01 => {
                // IPv4
                let mut b = [0u8; 6];
                conn.read_exact(&mut b).await?;
                let port = u16::from_be_bytes([b[4], b[5]]);
                format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
            }
            0x03 => {
                // 域名
                let mut len = [0u8; 1];
                conn.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                conn.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                conn.read_exact(&mut port).await?;
                format!(
                    "{}:{}",
                    String::from_utf8_lossy(&domain),
                    u16::from_be_bytes(port)
                )
            }
            0x04 => {
                // IPv6
                let mut b = [0u8; 18];
                conn.read_exact(&mut b).await?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&b[..16]);
                let port = u16::from_be_bytes([b[16], b[17]]);
                format!("[{}]:{}", std::net::Ipv6Addr::from(octets), port)
            }
            _ => {
                // 0x08 = Address type not supported
                conn.write_all(&socks5_reply(0x08)).await?;
                return Err(invalid_input("invalid SOCKS5 address type"));
            }
        };

        // ---- 4. 连接目标并桥接 ----
        let mut target_conn = match tokio::net::TcpStream::connect(target.as_str()).await {
            Ok(c) => c,
            Err(e) => {
                // 0x05 = Connection refused
                conn.write_all(&socks5_reply(0x05)).await?;
                return Err(Box::new(e));
            }
        };
        conn.write_all(&socks5_reply(0x00)).await?;
        tokio::io::copy_bidirectional(&mut conn, &mut target_conn).await?;

        Ok(())
    }
}

#[async_trait]
impl Plugin for Socks5Plugin {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle_socks5_request(conn).await
    }
}

/// TLS 卸载插件（https2http / tls2raw 同一实现）
///
/// 访客以 TLS 接入，插件终止 TLS（用 crt_path/key_path 或内置证书），
/// 解密后的明文流量桥接到 local_addr 的明文服务。
///
/// - `https2http`：HTTPS 访客 → 明文 HTTP 本地服务（frp 语义）
/// - `tls2raw`：TLS 访客 → 任意明文 TCP 本地服务
pub struct TlsOffloadPlugin {
    tls_config: rust_frp_net::TlsConfig,
    local_addr: String,
}

impl TlsOffloadPlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let local_addr = config
            .local_addr
            .clone()
            .ok_or_else(|| invalid_input("local_addr is required for https2http/tls2raw plugin"))?;

        // 证书：显式配置 crt_path/key_path 优先，否则内置自签名证书
        let tls_config = match (&config.crt_path, &config.key_path) {
            (Some(crt), Some(key)) => rust_frp_net::TlsConfig::new_server(crt, key)?,
            (None, None) => rust_frp_net::TlsConfig::new_server_with_runtime_cert()?,
            _ => {
                return Err(invalid_input(
                    "crt_path and key_path must be configured together",
                ))
            }
        };

        Ok(Self {
            tls_config,
            local_addr,
        })
    }
}

#[async_trait]
impl Plugin for TlsOffloadPlugin {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 终止访客侧 TLS
        let tls_conn = self.tls_config.accept_stream(conn).await?;
        // 明文桥接到本地服务
        let local = tokio::net::TcpStream::connect(&self.local_addr).await?;
        rust_frp_util::bridge_streams(tls_conn, local).await
    }
}

/// TLS 桥接插件（https2https）
///
/// 访客以 TLS 接入，插件终止 TLS 后重新以 TLS 连接 local_addr，
/// 双层 TLS 桥接（本地服务通常是自签证书，跳过验证）。
pub struct TlsBridgePlugin {
    server_tls: rust_frp_net::TlsConfig,
    client_tls: rust_frp_net::TlsConfig,
    local_addr: String,
}

impl TlsBridgePlugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let local_addr = config
            .local_addr
            .clone()
            .ok_or_else(|| invalid_input("local_addr is required for https2https plugin"))?;

        let server_tls = match (&config.crt_path, &config.key_path) {
            (Some(crt), Some(key)) => rust_frp_net::TlsConfig::new_server(crt, key)?,
            (None, None) => rust_frp_net::TlsConfig::new_server_with_runtime_cert()?,
            _ => {
                return Err(invalid_input(
                    "crt_path and key_path must be configured together",
                ))
            }
        };

        // 本地服务常为自签证书，跳过证书验证（仅加密不验证）
        let client_tls = rust_frp_net::TlsConfig::new_client_insecure()?;

        Ok(Self {
            server_tls,
            client_tls,
            local_addr,
        })
    }
}

#[async_trait]
impl Plugin for TlsBridgePlugin {
    async fn handle(
        &mut self,
        conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 终止访客侧 TLS
        let tls_conn = self.server_tls.accept_stream(conn).await?;
        // 重新以 TLS 连接本地服务
        let local_tcp = tokio::net::TcpStream::connect(&self.local_addr).await?;
        let local_tls = self
            .client_tls
            .connect_stream("localhost", local_tcp)
            .await?;
        rust_frp_util::bridge_streams(tls_conn, local_tls).await
    }
}

/// 构造 InvalidInput 错误的快捷方式
fn invalid_input(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.to_string(),
    ))
}

/// 构造 SOCKS5 应答：VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
fn socks5_reply(rep: u8) -> [u8; 10] {
    [0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// 插件管理器
pub struct PluginManager {
    factories: std::collections::HashMap<String, Box<dyn PluginFactory + Send + Sync>>,
}

impl PluginManager {
    pub fn new() -> Self {
        let mut factories: std::collections::HashMap<String, Box<dyn PluginFactory + Send + Sync>> =
            std::collections::HashMap::new();

        // 注册内置插件
        factories.insert(
            "unix_domain_socket".to_string(),
            Box::new(UnixDomainSocketPluginFactory {}),
        );
        factories.insert(
            "static_file".to_string(),
            Box::new(StaticFilePluginFactory {}),
        );
        factories.insert(
            "http_proxy".to_string(),
            Box::new(HttpProxyPluginFactory {}),
        );
        factories.insert("socks5".to_string(), Box::new(Socks5PluginFactory {}));
        // TLS 系插件（https2http/tls2raw 同一实现，https2https 双层 TLS）
        factories.insert(
            "https2http".to_string(),
            Box::new(TlsOffloadPluginFactory {}),
        );
        factories.insert("tls2raw".to_string(), Box::new(TlsOffloadPluginFactory {}));
        factories.insert(
            "https2https".to_string(),
            Box::new(TlsBridgePluginFactory {}),
        );
        // HTTP 反向代理桥接（明文 HTTP 接入 → 本地 HTTP / HTTPS）
        factories.insert(
            "http2http".to_string(),
            Box::new(HttpBridgePluginFactory {}),
        );
        factories.insert(
            "http2https".to_string(),
            Box::new(HttpBridgePluginFactory {}),
        );

        Self { factories }
    }

    pub fn create_plugin(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(factory) = self.factories.get(&config.r#type) {
            factory.create(config)
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported plugin type: {}", config.r#type),
            )))
        }
    }

    pub fn register_plugin(&mut self, name: &str, factory: Box<dyn PluginFactory + Send + Sync>) {
        self.factories.insert(name.to_string(), factory);
    }

    pub fn unregister_plugin(&mut self, name: &str) {
        self.factories.remove(name);
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Unix 域套接字插件工厂
struct UnixDomainSocketPluginFactory {}

impl PluginFactory for UnixDomainSocketPluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(UnixDomainSocketPlugin::new(config)?))
    }
}

/// 静态文件插件工厂
struct StaticFilePluginFactory {}

impl PluginFactory for StaticFilePluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(StaticFilePlugin::new(config)?))
    }
}

/// HTTP 代理插件工厂
struct HttpProxyPluginFactory {}

impl PluginFactory for HttpProxyPluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(HttpProxyPlugin::new(config)?))
    }
}

/// SOCKS5 代理插件工厂
struct Socks5PluginFactory {}

impl PluginFactory for Socks5PluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(Socks5Plugin::new(config)?))
    }
}

/// TLS 卸载插件工厂（https2http / tls2raw）
struct TlsOffloadPluginFactory {}

impl PluginFactory for TlsOffloadPluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(TlsOffloadPlugin::new(config)?))
    }
}

/// TLS 桥接插件工厂（https2https）
struct TlsBridgePluginFactory {}

impl PluginFactory for TlsBridgePluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(TlsBridgePlugin::new(config)?))
    }
}

/// HTTP 反向代理桥接插件工厂（http2http / http2https）
///
/// 两者的差别仅在于转发目标协议（明文 / TLS），
/// 由 [`HttpBridgePlugin::new`] 依据 `config.type` 判定。
struct HttpBridgePluginFactory {}

impl PluginFactory for HttpBridgePluginFactory {
    fn create(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn Plugin>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::new(HttpBridgePlugin::new(config)?))
    }
}

#[cfg(test)]
mod static_file_auth_tests {
    use super::*;
    use rust_frp_config::PluginConfig;

    fn plugin(user: Option<&str>, password: Option<&str>) -> StaticFilePlugin {
        let cfg = PluginConfig {
            local_path: Some("/tmp".to_string()),
            http_user: user.map(|s| s.to_string()),
            http_password: password.map(|s| s.to_string()),
            ..Default::default()
        };
        StaticFilePlugin::new(&cfg).expect("plugin build failed")
    }

    /// 构造带 Authorization 头的请求行并执行校验
    fn check(p: &StaticFilePlugin, headers: &[String]) -> bool {
        let mut lines: Vec<&str> = vec!["GET /index.html HTTP/1.1", "Host: x"];
        lines.extend(headers.iter().map(|s| s.as_str()));
        p.check_basic_auth(&lines)
    }

    fn basic_header(user: &str, password: &str) -> String {
        format!(
            "Authorization: Basic {}",
            base64::encode(format!("{}:{}", user, password))
        )
    }

    /// 未配置 http_user → 匿名放行
    #[test]
    fn anonymous_when_no_user_configured() {
        assert!(check(&plugin(None, None), &[]));
    }

    /// 配置了凭据但请求无 Authorization 头 → 拒绝
    #[test]
    fn missing_header_rejected() {
        assert!(!check(&plugin(Some("u"), Some("p")), &[]));
    }

    /// 非 Basic scheme（如 Bearer）→ 拒绝
    #[test]
    fn wrong_scheme_rejected() {
        assert!(!check(
            &plugin(Some("u"), Some("p")),
            &["Authorization: Bearer abc".to_string()]
        ));
    }

    /// 非法 base64 → 拒绝
    #[test]
    fn invalid_base64_rejected() {
        assert!(!check(
            &plugin(Some("u"), Some("p")),
            &["Authorization: Basic !!!bad!!!".to_string()]
        ));
    }

    /// 解码后无冒号分隔 → 拒绝
    #[test]
    fn malformed_credentials_rejected() {
        let h = format!("Authorization: Basic {}", base64::encode("nocolon"));
        assert!(!check(&plugin(Some("u"), Some("p")), &[h]));
    }

    /// 错误用户名/错误密码 → 拒绝；正确凭据 → 放行
    #[test]
    fn credential_match() {
        assert!(check(
            &plugin(Some("u"), Some("p")),
            &[basic_header("u", "p")]
        ));
        assert!(!check(
            &plugin(Some("u"), Some("p")),
            &[basic_header("x", "p")]
        ));
        assert!(!check(
            &plugin(Some("u"), Some("p")),
            &[basic_header("u", "x")]
        ));
    }

    /// 头名与 scheme 大小写不敏感
    #[test]
    fn case_insensitive_header_and_scheme() {
        let h = format!("authorization: basic {}", base64::encode("u:p"));
        assert!(check(&plugin(Some("u"), Some("p")), &[h]));
    }

    /// 未配置 http_password 时要求空密码精确匹配（比"任意密码可过"更严格）
    #[test]
    fn empty_password_requires_empty() {
        assert!(check(&plugin(Some("u"), None), &[basic_header("u", "")]));
        assert!(!check(
            &plugin(Some("u"), None),
            &[basic_header("u", "anything")]
        ));
    }
}

#[cfg(test)]
mod proxy_plugin_auth_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ---------------- http_proxy ----------------

    fn http_plugin(user: Option<&str>, password: Option<&str>) -> HttpProxyPlugin {
        let cfg = PluginConfig {
            r#type: "http_proxy".to_string(),
            http_user: user.map(str::to_string),
            http_password: password.map(str::to_string),
            ..Default::default()
        };
        HttpProxyPlugin::new(&cfg).expect("http proxy build failed")
    }

    fn proxy_auth_header(user: &str, password: &str) -> String {
        format!(
            "Proxy-Authorization: Basic {}",
            base64::encode(format!("{}:{}", user, password))
        )
    }

    fn check_http(p: &HttpProxyPlugin, headers: &[String]) -> bool {
        let mut lines: Vec<&str> = vec!["CONNECT example.com:443 HTTP/1.1", "Host: example.com"];
        lines.extend(headers.iter().map(|s| s.as_str()));
        p.check_proxy_auth(&lines)
    }

    /// 未配置凭据 → 匿名放行
    #[test]
    fn http_proxy_anonymous_when_unconfigured() {
        assert!(check_http(&http_plugin(None, None), &[]));
    }

    /// 配置凭据但无 Proxy-Authorization → 拒绝
    #[test]
    fn http_proxy_missing_header_rejected() {
        assert!(!check_http(&http_plugin(Some("u"), Some("p")), &[]));
    }

    /// 非 Basic scheme → 拒绝
    #[test]
    fn http_proxy_wrong_scheme_rejected() {
        assert!(!check_http(
            &http_plugin(Some("u"), Some("p")),
            &["Proxy-Authorization: Bearer abc".to_string()]
        ));
    }

    /// 非法 base64 / 无冒号 → 拒绝
    #[test]
    fn http_proxy_malformed_rejected() {
        assert!(!check_http(
            &http_plugin(Some("u"), Some("p")),
            &["Proxy-Authorization: Basic !!!".to_string()]
        ));
        let h = format!("Proxy-Authorization: Basic {}", base64::encode("nocolon"));
        assert!(!check_http(&http_plugin(Some("u"), Some("p")), &[h]));
    }

    /// 凭据比对（常量时间）：全对放行，任一错拒绝
    #[test]
    fn http_proxy_credential_match() {
        assert!(check_http(
            &http_plugin(Some("u"), Some("p")),
            &[proxy_auth_header("u", "p")]
        ));
        assert!(!check_http(
            &http_plugin(Some("u"), Some("p")),
            &[proxy_auth_header("x", "p")]
        ));
        assert!(!check_http(
            &http_plugin(Some("u"), Some("p")),
            &[proxy_auth_header("u", "x")]
        ));
    }

    /// 头名与 scheme 大小写不敏感
    #[test]
    fn http_proxy_case_insensitive() {
        let h = format!("proxy-authorization: basic {}", base64::encode("u:p"));
        assert!(check_http(&http_plugin(Some("u"), Some("p")), &[h]));
    }

    /// 端到端：无凭据 CONNECT 必须收到 407 + Proxy-Authenticate，且不触碰目标
    #[tokio::test]
    async fn http_proxy_returns_407_without_credentials() {
        let mut plugin = http_plugin(Some("u"), Some("p"));
        let (mut client, server) = tokio::io::duplex(4096);

        let client_side = async move {
            client
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 256];
            let n = client.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        };
        let (resp, _) = tokio::join!(client_side, plugin.handle(Box::new(server)));
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "unexpected response: {resp}"
        );
        assert!(
            resp.to_ascii_lowercase()
                .contains("proxy-authenticate: basic"),
            "missing Proxy-Authenticate: {resp}"
        );
    }

    // ---------------- socks5 ----------------

    fn socks5_plugin(user: Option<&str>, password: Option<&str>) -> Socks5Plugin {
        let cfg = PluginConfig {
            r#type: "socks5".to_string(),
            username: user.map(str::to_string),
            password: password.map(str::to_string),
            ..Default::default()
        };
        Socks5Plugin::new(&cfg).expect("socks5 build failed")
    }

    #[test]
    fn socks5_needs_auth_flag() {
        assert!(!socks5_plugin(None, None).needs_auth());
        assert!(socks5_plugin(Some("u"), Some("p")).needs_auth());
        assert!(socks5_plugin(Some("u"), None).needs_auth());
    }

    #[test]
    fn socks5_method_selection() {
        // 需认证：仅当客户端提供 0x02 才可用
        assert_eq!(Socks5Plugin::select_method(&[0x00], true), None);
        assert_eq!(Socks5Plugin::select_method(&[0x00, 0x02], true), Some(0x02));
        // 无需认证：优先 0x00
        assert_eq!(
            Socks5Plugin::select_method(&[0x00, 0x02], false),
            Some(0x00)
        );
        assert_eq!(Socks5Plugin::select_method(&[0x02], false), None);
    }

    #[test]
    fn socks5_verify_credentials() {
        let p = socks5_plugin(Some("alice"), Some("s3cret"));
        assert!(p.verify_credentials(b"alice", b"s3cret"));
        assert!(!p.verify_credentials(b"alice", b"wrong"));
        assert!(!p.verify_credentials(b"bob", b"s3cret"));
    }

    /// 未配置凭据 → 使用「无认证」方法（0x00）
    #[tokio::test]
    async fn socks5_no_auth_when_unconfigured() {
        let mut plugin = socks5_plugin(None, None);
        let (mut client, server) = tokio::io::duplex(4096);

        let client_side = async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            sel
        };
        let (sel, _) = tokio::join!(client_side, plugin.handle(Box::new(server)));
        assert_eq!(sel, [0x05, 0x00]);
    }

    /// 需认证但客户端只提供 0x00 → 回 0xFF 并拒绝
    #[tokio::test]
    async fn socks5_rejects_when_no_userpass_method_offered() {
        let mut plugin = socks5_plugin(Some("u"), Some("p"));
        let (mut client, server) = tokio::io::duplex(4096);

        let client_side = async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            sel
        };
        let (sel, _) = tokio::join!(client_side, plugin.handle(Box::new(server)));
        assert_eq!(sel, [0x05, 0xFF]);
    }

    /// 密码错误 → RFC 1929 回 [0x01, 0x01]
    #[tokio::test]
    async fn socks5_auth_failure_status_is_one() {
        let mut plugin = socks5_plugin(Some("alice"), Some("s3cret"));
        let (mut client, server) = tokio::io::duplex(4096);

        let client_side = async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [0x05, 0x02]);
            let mut auth = vec![0x01u8, 5];
            auth.extend_from_slice(b"alice");
            auth.push(5);
            auth.extend_from_slice(b"wrong");
            client.write_all(&auth).await.unwrap();
            let mut res = [0u8; 2];
            client.read_exact(&mut res).await.unwrap();
            res
        };
        let (res, _) = tokio::join!(client_side, plugin.handle(Box::new(server)));
        assert_eq!(res, [0x01, 0x01]);
    }

    /// 认证成功 → CONNECT 成功 → 数据双向桥接到本地 echo 服务
    #[tokio::test]
    async fn socks5_auth_success_then_connect_bridges() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();

        let echo = async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 8];
                if let Ok(n) = s.read(&mut b).await {
                    let _ = s.write_all(&b[..n]).await;
                }
            }
        };

        let mut plugin = socks5_plugin(Some("alice"), Some("s3cret"));
        let (mut client, server) = tokio::io::duplex(4096);

        let client_side = async move {
            // 方法协商
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut sel = [0u8; 2];
            client.read_exact(&mut sel).await.unwrap();
            assert_eq!(sel, [0x05, 0x02]);
            // RFC 1929 认证（正确凭据）
            let mut auth = vec![0x01u8, 5];
            auth.extend_from_slice(b"alice");
            auth.push(6);
            auth.extend_from_slice(b"s3cret");
            client.write_all(&auth).await.unwrap();
            let mut ar = [0u8; 2];
            client.read_exact(&mut ar).await.unwrap();
            assert_eq!(ar, [0x01, 0x00]);
            // CONNECT 127.0.0.1:target_port
            let mut req = vec![0x05u8, 0x01, 0x00, 0x01, 127, 0, 0, 1];
            req.extend_from_slice(&target_port.to_be_bytes());
            client.write_all(&req).await.unwrap();
            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00, "connect reply: {rep:?}");
            // 数据往返
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            buf
        };

        let (_, echoed, _) = tokio::join!(echo, client_side, plugin.handle(Box::new(server)));
        assert_eq!(&echoed, b"ping");
    }
}
