use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use rust_frp_net::FrpConn;

/// 消息类型
#[derive(Debug, Deserialize, Serialize)]
pub enum Message {
    Login(LoginMsg),
    LoginResp(LoginRespMsg),
    RegisterProxy(RegisterProxyMsg),
    RegisterProxyResp(RegisterProxyRespMsg),
    NewWorkConn(NewWorkConnMsg),
    StartWorkConn(StartWorkConnMsg),
    NewVisitorConn(NewVisitorConnMsg),
    NewVisitorConnResp(NewVisitorConnRespMsg),
    Ping(PingMsg),
    Pong(PongMsg),
    ProxyStatus(ProxyStatusMsg),
    ProxyStatusResp(ProxyStatusRespMsg),
}

/// 登录消息
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginMsg {
    pub arch: String,
    pub os: String,
    pub hostname: String,
    pub pool_count: u32,
    pub user: String,
    pub client_id: String,
    pub version: String,
    pub timestamp: i64,
    pub run_id: String,
    pub token: String,
    pub metas: std::collections::HashMap<String, String>,
    pub client_spec: Option<ClientSpec>,
}

/// 客户端规范
#[derive(Debug, Deserialize, Serialize)]
pub struct ClientSpec {
    pub r#type: String,
    pub always_auth_pass: bool,
}

/// 登录响应消息
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginRespMsg {
    pub version: String,
    pub run_id: String,
    pub error: String,
}

/// 代理注册消息
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterProxyMsg {
    pub proxy: rust_frp_config::ProxyConfig,
}

/// 代理注册响应消息
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterProxyRespMsg {
    pub name: String,
    pub error: String,
}

/// 新工作连接消息
#[derive(Debug, Deserialize, Serialize)]
pub struct NewWorkConnMsg {
    pub run_id: String,
    pub proxy_name: String,
    pub timestamp: i64,
    pub sign_key: String,
    pub use_encryption: bool,
    pub use_compression: bool,
}

/// 开始工作连接消息
#[derive(Debug, Deserialize, Serialize)]
pub struct StartWorkConnMsg {
    pub error: String,
}

/// 新访问者连接消息
#[derive(Debug, Deserialize, Serialize)]
pub struct NewVisitorConnMsg {
    pub run_id: String,
    pub proxy_name: String,
    pub timestamp: i64,
    pub sign_key: String,
    pub use_encryption: bool,
    pub use_compression: bool,
}

/// 新访问者连接响应消息
#[derive(Debug, Deserialize, Serialize)]
pub struct NewVisitorConnRespMsg {
    pub proxy_name: String,
    pub error: String,
}

/// Ping 消息
#[derive(Debug, Deserialize, Serialize)]
pub struct PingMsg {
    pub timestamp: i64,
}

/// Pong 消息
#[derive(Debug, Deserialize, Serialize)]
pub struct PongMsg {
    pub timestamp: i64,
}

/// 代理状态消息
#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyStatusMsg {
    pub name: String,
}

/// 代理状态响应消息
#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyStatusRespMsg {
    pub name: String,
    pub status: String,
    pub error: String,
}

/// 消息读取器
pub async fn read_message<T: AsyncRead + Unpin>(conn: &mut T) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0; 4];
    conn.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut msg_buf = vec![0; len];
    conn.read_exact(&mut msg_buf).await?;
    let msg: Message = serde_json::from_slice(&msg_buf)?;
    Ok(msg)
}

/// 消息写入器
pub async fn write_message<T: AsyncWrite + Unpin>(conn: &mut T, msg: &Message) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg_buf = serde_json::to_vec(msg)?;
    let len = msg_buf.len() as u32;
    let len_buf = len.to_be_bytes();
    conn.write_all(&len_buf).await?;
    conn.write_all(&msg_buf).await?;
    Ok(())
}

/// 控制连接
pub struct ControlConn {
    conn: Box<dyn FrpConn>,
}

impl ControlConn {
    pub fn new(conn: Box<dyn FrpConn>) -> Self {
        Self {
            conn,
        }
    }

    pub async fn read_message(&mut self) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        read_message(&mut self.conn).await
    }

    pub async fn write_message(&mut self, msg: &Message) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        write_message(&mut self.conn, msg).await
    }

    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.conn.remote_addr()
    }
}

/// 工作连接
pub struct WorkConn {
    conn: Box<dyn FrpConn>,
    proxy_name: String,
}

impl WorkConn {
    pub fn new(conn: Box<dyn FrpConn>, proxy_name: String) -> Self {
        Self {
            conn,
            proxy_name,
        }
    }

    pub fn proxy_name(&self) -> &str {
        &self.proxy_name
    }

    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.conn.remote_addr()
    }
}

/// 代理管理器 trait
#[async_trait::async_trait]
pub trait ProxyManager {
    async fn add_proxy(&self, config: rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn get_proxy_status(&self, name: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>;
}

/// 访问者管理器 trait
#[async_trait::async_trait]
pub trait VisitorManager {
    async fn add_visitor(&self, config: rust_frp_config::VisitorConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn remove_visitor(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
