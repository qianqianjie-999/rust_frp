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
use std::fs::File;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

/// Combined trait for AsyncRead + AsyncWrite
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for T {}

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
#[allow(dead_code)]
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

        // 读取文件内容
        let mut file = File::open(&canonical_path)?;
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut content)?;

        // 发送 HTTP 响应
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            content.len()
        );
        conn.write_all(response.as_bytes()).await?;
        conn.write_all(&content).await?;

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

/// HTTP 代理插件
#[allow(dead_code)]
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
        if parts.len() < 3 || parts[0] != "CONNECT" {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP CONNECT request",
            )));
        }

        let target = parts[1];

        // 连接到目标服务器
        let target_addr = target.parse::<std::net::SocketAddr>()?;
        let mut target_conn = tokio::net::TcpStream::connect(target_addr).await?;

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
#[allow(dead_code)]
pub struct Socks5Plugin {
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Plugin {
    pub fn new(config: &PluginConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            username: config.http_user.clone(),
            password: config.http_password.clone(),
        })
    }

    /// 处理 SOCKS5 代理请求
    async fn handle_socks5_request(
        &self,
        mut conn: Box<dyn AsyncStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取 SOCKS5 握手请求
        let mut buf = [0; 256];
        let n = conn.read(&mut buf).await?;

        // 验证 SOCKS5 版本
        if n < 2 || buf[0] != 0x05 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 version",
            )));
        }

        // 发送 SOCKS5 握手响应
        let response = [0x05, 0x00]; // 无认证
        conn.write_all(&response).await?;

        // 读取 SOCKS5 请求
        let n = conn.read(&mut buf).await?;
        if n < 4 || buf[0] != 0x05 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 request",
            )));
        }

        // 解析 SOCKS5 请求
        let cmd = buf[1];
        if cmd != 0x01 {
            // CONNECT
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported SOCKS5 command",
            )));
        }

        // 解析目标地址
        let addr_type = buf[3];
        #[allow(unused_assignments)]
        let mut target_addr = String::new();
        #[allow(unused_assignments)]
        let mut target_port = 0;

        match addr_type {
            0x01 => {
                // IPv4
                if n < 10 {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid SOCKS5 IPv4 address",
                    )));
                }
                target_addr = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                target_port = ((buf[8] as u16) << 8) | (buf[9] as u16);
            }
            0x03 => {
                // 域名
                let len = buf[4] as usize;
                if n < 5 + len + 2 {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid SOCKS5 domain address",
                    )));
                }
                target_addr = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                target_port = ((buf[5 + len] as u16) << 8) | (buf[5 + len + 1] as u16);
            }
            0x04 => {
                // IPv6
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPv6 not supported",
                )));
            }
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SOCKS5 address type",
                )));
            }
        }

        // 连接到目标服务器
        let target = format!("{}:{}", target_addr, target_port);
        let mut target_conn = tokio::net::TcpStream::connect(target).await?;

        // 发送 SOCKS5 响应
        let response = [
            0x05, // 版本
            0x00, // 成功
            0x00, // 保留
            0x01, // IPv4
            0x00, 0x00, 0x00, 0x00, // 地址
            0x00, 0x00, // 端口
        ];
        conn.write_all(&response).await?;

        // 双向转发数据
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
            (None, None) => rust_frp_net::TlsConfig::new_server_with_builtin_cert()?,
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
            (None, None) => rust_frp_net::TlsConfig::new_server_with_builtin_cert()?,
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
