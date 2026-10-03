//! HTTP/HTTPS 虚拟主机：请求解析、路由与监听器

use rust_frp_net::TlsConfig;
use std::net::SocketAddr;
use tokio::sync::RwLock;

/// HTTP 请求信息
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: std::collections::HashMap<String, String>,
    pub host: String,
}

impl HttpRequestInfo {
    /// 从原始 HTTP 请求数据解析
    pub fn parse(data: &[u8]) -> Option<Self> {
        let request_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return None;
        }

        // 解析请求行
        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        // 解析请求头
        let mut headers = std::collections::HashMap::new();
        let mut host = String::new();

        for line in &lines[1..] {
            if line.is_empty() {
                break;
            }
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase();
                let value = line[idx + 1..].trim().to_string();
                if key == "host" {
                    // 去除端口号
                    host = value.split(':').next().unwrap_or(&value).to_string();
                }
                headers.insert(key, value);
            }
        }

        if host.is_empty() {
            return None;
        }

        Some(Self {
            method,
            path,
            version,
            headers,
            host,
        })
    }

    /// 检查是否是 WebSocket 升级请求
    pub fn is_websocket_upgrade(&self) -> bool {
        // 检查 Connection 头是否包含 "Upgrade"
        if let Some(connection) = self.headers.get("connection") {
            if !connection.to_lowercase().contains("upgrade") {
                return false;
            }
        } else {
            return false;
        }

        // 检查 Upgrade 头是否为 "websocket"
        if let Some(upgrade) = self.headers.get("upgrade") {
            upgrade.to_lowercase() == "websocket"
        } else {
            false
        }
    }

    /// 获取 Sec-WebSocket-Key
    pub fn get_websocket_key(&self) -> Option<&str> {
        self.headers.get("sec-websocket-key").map(|s| s.as_str())
    }

    /// 生成 WebSocket 接受密钥
    pub fn generate_websocket_accept_key(key: &str) -> String {
        use base64::encode;
        use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

        let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, magic_string);

        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(combined.as_bytes());
        let digest = context.finish();

        encode(digest.as_ref())
    }
}

/// HTTP 虚拟主机路由器
pub struct HttpVhostRouter {
    // domain -> proxy_name
    domain_map: RwLock<std::collections::HashMap<String, String>>,
    // proxy_name -> proxy config
    proxy_configs: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
}

impl Default for HttpVhostRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpVhostRouter {
    pub fn new() -> Self {
        Self {
            domain_map: RwLock::new(std::collections::HashMap::new()),
            proxy_configs: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册 HTTP 代理的域名映射
    pub async fn register_proxy(
        &self,
        proxy_name: String,
        domains: Vec<String>,
        config: rust_frp_config::ProxyConfig,
    ) {
        let mut domain_map = self.domain_map.write().await;
        for domain in domains {
            log::info!("Registering domain '{}' for proxy '{}'", domain, proxy_name);
            domain_map.insert(domain, proxy_name.clone());
        }

        let mut proxy_configs = self.proxy_configs.write().await;
        proxy_configs.insert(proxy_name, config);
    }

    /// 注销 HTTP 代理
    pub async fn unregister_proxy(&self, proxy_name: &str) {
        let mut domain_map = self.domain_map.write().await;
        domain_map.retain(|_, v| v != proxy_name);

        let mut proxy_configs = self.proxy_configs.write().await;
        proxy_configs.remove(proxy_name);
    }

    /// 根据 Host 查找代理名称
    pub async fn find_proxy_by_host(&self, host: &str) -> Option<String> {
        let domain_map = self.domain_map.read().await;

        // 首先尝试精确匹配
        if let Some(proxy_name) = domain_map.get(host) {
            return Some(proxy_name.clone());
        }

        // 尝试子域名匹配
        for (domain, proxy_name) in domain_map.iter() {
            if host.ends_with(domain) {
                return Some(proxy_name.clone());
            }
        }

        None
    }

    /// 获取代理配置
    pub async fn get_proxy_config(&self, proxy_name: &str) -> Option<rust_frp_config::ProxyConfig> {
        let proxy_configs = self.proxy_configs.read().await;
        proxy_configs.get(proxy_name).cloned()
    }
}

/// HTTP 虚拟主机监听器
pub struct HttpVhostListener {
    inner: std::sync::Arc<tokio::net::TcpListener>,
}

impl HttpVhostListener {
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
        })
    }

    pub async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr), std::io::Error> {
        self.inner.accept().await
    }

    pub fn get_listener(&self) -> std::sync::Arc<tokio::net::TcpListener> {
        self.inner.clone()
    }
}

/// HTTPS 虚拟主机监听器
pub struct HttpsVhostListener {
    inner: std::sync::Arc<tokio::net::TcpListener>,
    pub(crate) tls_config: TlsConfig,
}

impl HttpsVhostListener {
    pub async fn bind(addr: &SocketAddr, tls_config: TlsConfig) -> Result<Self, std::io::Error> {
        let inner = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
            tls_config,
        })
    }

    pub async fn accept(
        &self,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            SocketAddr,
        ),
        std::io::Error,
    > {
        let (conn, addr) = self.inner.accept().await?;
        let tls_conn = self.tls_config.accept(conn).await?;
        Ok((tls_conn, addr))
    }

    pub fn get_listener(&self) -> std::sync::Arc<tokio::net::TcpListener> {
        self.inner.clone()
    }
}
