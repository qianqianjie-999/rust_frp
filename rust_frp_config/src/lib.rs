use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::env;
use glob::glob;

/// 服务器配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub bind_port: u16,
    pub kcp_bind_port: Option<u16>,
    pub quic_bind_port: Option<u16>,
    pub vhost_http_port: Option<u16>,
    pub vhost_https_port: Option<u16>,
    pub tcpmux_http_connect_port: Option<u16>,
    pub web_server: WebServerConfig,
    pub auth: AuthConfig,
    pub transport: TransportConfig,
    pub allow_ports: Option<Vec<PortRange>>,
    pub custom_404_page: Option<String>,
    pub includes: Option<Vec<String>>,
}

/// 客户端配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub user: Option<String>,
    pub client_id: Option<String>,
    pub web_server: WebServerConfig,
    pub auth: AuthConfig,
    pub transport: TransportConfig,
    pub proxies: Vec<ProxyConfig>,
    pub visitors: Vec<VisitorConfig>,
    pub includes: Option<Vec<String>>,
}

/// Web 服务器配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebServerConfig {
    pub addr: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub tls: Option<TlsConfig>,
}

/// 认证配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    pub method: String,
    pub token: Option<String>,
    pub oidc: Option<OidcConfig>,
}

/// OIDC 配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_endpoint_url: String,
}

/// 传输配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransportConfig {
    pub protocol: String,
    pub tls: Option<TlsConfig>,
    pub tcp_mux: bool,
    pub pool_count: u32,
    pub bandwidth_limit: Option<String>,
}

/// TLS 配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub trusted_ca_file: Option<String>,
    pub force: bool,
}

/// 端口范围
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PortRange {
    pub start: Option<u16>,
    pub end: Option<u16>,
    pub single: Option<u16>,
}

/// 代理配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    pub name: String,
    pub r#type: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: Option<u16>,
    pub custom_domains: Option<Vec<String>>,
    pub subdomain: Option<String>,
    pub locations: Option<Vec<String>>,
    pub host_header_rewrite: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<String>,
    pub health_check: Option<HealthCheckConfig>,
    pub transport: Option<TransportConfig>,
    pub plugin: Option<PluginConfig>,
}

/// 访问者配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VisitorConfig {
    pub name: String,
    pub r#type: String,
    pub server_name: String,
    pub secret_key: Option<String>,
    pub bind_addr: String,
    pub bind_port: u16,
    pub transport: Option<TransportConfig>,
}

/// 健康检查配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    pub r#type: String,
    pub timeout_seconds: u32,
    pub max_failed: u32,
    pub interval_seconds: u32,
    pub path: Option<String>,
}

/// 插件配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PluginConfig {
    pub r#type: String,
    pub unix_path: Option<String>,
    pub local_path: Option<String>,
    pub strip_prefix: Option<String>,
    pub http_user: Option<String>,
    pub http_password: Option<String>,
    pub local_addr: Option<String>,
    pub crt_path: Option<String>,
    pub key_path: Option<String>,
}

/// 配置加载器
pub struct ConfigLoader;

impl ConfigLoader {
    /// 从文件加载服务器配置
    pub fn load_server_config<P: AsRef<Path>>(path: P) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let mut config = Self::load_config_from_file(path)?;
        Self::process_includes(&mut config)?;
        Self::replace_environment_variables(&mut config)?;
        Self::validate_server_config(&config)?;
        Ok(config)
    }

    /// 从文件加载客户端配置
    pub fn load_client_config<P: AsRef<Path>>(path: P) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = Self::load_config_from_file(path)?;
        Self::process_includes(&mut config)?;
        Self::replace_environment_variables(&mut config)?;
        Self::validate_client_config(&config)?;
        Ok(config)
    }

    /// 从文件加载配置
    fn load_config_from_file<P: AsRef<Path>, T: serde::de::DeserializeOwned>(path: P) -> Result<T, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Self::parse_config(&content)
    }

    /// 解析配置
    fn parse_config<T: serde::de::DeserializeOwned>(content: &str) -> Result<T, Box<dyn std::error::Error>> {
        // 尝试 TOML 解析
        if let Ok(config) = toml::from_str(content) {
            return Ok(config);
        }
        // 尝试 YAML 解析
        if let Ok(config) = serde_yaml::from_str(content) {
            return Ok(config);
        }
        // 尝试 JSON 解析
        if let Ok(config) = serde_json::from_str(content) {
            return Ok(config);
        }
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse config file",
        )))
    }

    /// 处理配置文件包含
    fn process_includes(config: &mut ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(includes) = &config.includes {
            for pattern in includes {
                let files = glob(pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config = Self::load_config_from_file(path)?;
                            // 合并配置
                            Self::merge_server_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 处理配置文件包含
    fn process_includes_client(config: &mut ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(includes) = &config.includes {
            for pattern in includes {
                let files = glob(pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config = Self::load_config_from_file(path)?;
                            // 合并配置
                            Self::merge_client_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 合并服务器配置
    fn merge_server_config(target: &mut ServerConfig, source: &ServerConfig) {
        if source.bind_addr != "" {
            target.bind_addr = source.bind_addr.clone();
        }
        if source.bind_port != 0 {
            target.bind_port = source.bind_port;
        }
        if source.kcp_bind_port.is_some() {
            target.kcp_bind_port = source.kcp_bind_port;
        }
        if source.quic_bind_port.is_some() {
            target.quic_bind_port = source.quic_bind_port;
        }
        if source.vhost_http_port.is_some() {
            target.vhost_http_port = source.vhost_http_port;
        }
        if source.vhost_https_port.is_some() {
            target.vhost_https_port = source.vhost_https_port;
        }
        if source.tcpmux_http_connect_port.is_some() {
            target.tcpmux_http_connect_port = source.tcpmux_http_connect_port;
        }
        target.proxies.extend(source.proxies.clone());
    }

    /// 合并客户端配置
    fn merge_client_config(target: &mut ClientConfig, source: &ClientConfig) {
        if source.server_addr != "" {
            target.server_addr = source.server_addr.clone();
        }
        if source.server_port != 0 {
            target.server_port = source.server_port;
        }
        if source.user.is_some() {
            target.user = source.user.clone();
        }
        if source.client_id.is_some() {
            target.client_id = source.client_id.clone();
        }
        target.proxies.extend(source.proxies.clone());
        target.visitors.extend(source.visitors.clone());
    }

    /// 替换环境变量
    fn replace_environment_variables(config: &mut ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        // 这里应该实现环境变量替换逻辑
        // 暂时简单实现
        Ok(())
    }

    /// 替换环境变量
    fn replace_environment_variables_client(config: &mut ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
        // 这里应该实现环境变量替换逻辑
        // 暂时简单实现
        Ok(())
    }

    /// 验证服务器配置
    fn validate_server_config(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        if config.bind_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bind_port is required",
            )));
        }
        Ok(())
    }

    /// 验证客户端配置
    fn validate_client_config(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
        if config.server_addr == "" {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_addr is required",
            )));
        }
        if config.server_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_port is required",
            )));
        }
        Ok(())
    }
}

