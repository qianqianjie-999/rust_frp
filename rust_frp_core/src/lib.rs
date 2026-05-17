//! # rust_frp_core - FRP 核心协议定义
//!
//! 本模块定义了 FRP (Fast Reverse Proxy) 协议的所有核心消息类型和通信原语。
//!
//! ## 协议架构
//!
//! FRP 协议采用 JSON 序列化进行消息传输，消息格式为：
//! - 4 字节：消息长度（大端序 u32）
//! - N 字节：JSON 编码的消息内容
//!
//! ## 消息类型
//!
//! ### 控制平面消息
//! - `Login` / `LoginResp` - 客户端认证和会话建立
//! - `Ping` / `Pong` - 心跳保活
//!
//! ### 代理管理消息
//! - `RegisterProxy` / `RegisterProxyResp` - 代理注册
//! - `ProxyStatus` / `ProxyStatusResp` - 代理状态查询
//! - `Disconnect` - 断开连接通知
//!
//! ### 工作连接消息
//! - `ReqWorkConn` - 服务器请求工作连接
//! - `NewWorkConn` / `StartWorkConn` - 工作连接建立
//!
//! ### 访问者消息
//! - `NewVisitorConn` / `NewVisitorConnResp` - 访问者连接（TCP 打孔）

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use rust_frp_net::FrpConn;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),
    #[error("JSON serialization failed: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// 消息类型枚举 - FRP 协议所有消息的联合类型
///
/// # 消息流概述
///
/// ## 1. 客户端登录流程
/// ```text
/// Client                          Server
///   |                               |
///   |--- LoginMsg ----------------->|
///   |<-- LoginRespMsg --------------|
/// ```
///
/// ## 2. 代理注册流程
/// ```text
/// Client                          Server
///   |                               |
///   |--- RegisterProxyMsg --------->|
///   |<-- RegisterProxyRespMsg ------|
/// ```
///
/// ## 3. 工作连接建立
/// ```text
/// Client                          Server
///   |                               |
///   |<-- ReqWorkConnMsg ------------|
///   |--- NewWorkConnMsg ----------->|
/// ```
///
/// ## 4. 心跳保活
/// ```text
/// Client                          Server
///   |                               |
///   |--- PingMsg ------------------>|
///   |<-- PongMsg -------------------|
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// 客户端登录请求
    /// 包含客户端基本信息、认证令牌、连接池配置等
    Login(LoginMsg),

    /// 服务器登录响应
    /// 包含版本验证结果、运行ID、错误信息（若登录失败）
    LoginResp(LoginRespMsg),

    /// 代理注册请求
    /// 包含完整的代理配置（代理名称、类型、本地地址等）
    RegisterProxy(RegisterProxyMsg),

    /// 代理注册响应
    /// 包含注册结果和错误信息
    RegisterProxyResp(RegisterProxyRespMsg),

    /// 服务器请求新工作连接
    /// 当服务器需要为代理创建新的工作连接时发送
    ReqWorkConn(ReqWorkConnMsg),

    /// 客户端通知服务器有新工作连接可用
    /// 包含签名密钥用于验证连接合法性
    NewWorkConn(NewWorkConnMsg),

    /// 服务器响应新工作连接
    /// 包含连接建立结果和错误信息
    StartWorkConn(StartWorkConnMsg),

    /// 访问者连接请求（用于 TCP 打孔）
    /// 包含目标代理名称和签名密钥
    NewVisitorConn(NewVisitorConnMsg),

    /// 访问者连接响应
    NewVisitorConnResp(NewVisitorConnRespMsg),

    /// 客户端心跳请求
    Ping(PingMsg),

    /// 服务器心跳响应
    Pong(PongMsg),

    /// 代理状态查询请求
    ProxyStatus(ProxyStatusMsg),

    /// 代理状态查询响应
    ProxyStatusResp(ProxyStatusRespMsg),

    /// 连接断开通知
    Disconnect(DisconnectMsg),
}

/// 登录消息 - 客户端连接服务器时发送的第一个消息
///
/// # 字段说明
///
/// - `arch`: 客户端 CPU 架构（如 "amd64", "aarch64"）
/// - `os`: 操作系统（如 "linux", "windows", "darwin"）
/// - `hostname`: 客户端主机名
/// - `pool_count`: 连接池大小，客户端预建立的工作连接数量
/// - `user`: 用户标识（用于多用户场景）
/// - `client_id`: 客户端唯一标识符
/// - `version`: FRP 协议版本
/// - `timestamp`: 客户端时间戳（毫秒），用于防重放攻击
/// - `run_id`: 本次运行唯一标识符
/// - `token`: 认证令牌，与服务器配置比对验证
/// - `metas`: 元数据键值对，用于扩展信息
/// - `client_spec`: 客户端规范，指定客户端类型和特性
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginMsg {
    /// 客户端 CPU 架构
    pub arch: String,
    /// 操作系统类型
    pub os: String,
    /// 客户端主机名
    pub hostname: String,
    /// 工作连接池大小
    pub pool_count: u32,
    /// 用户标识
    pub user: String,
    /// 客户端唯一 ID
    pub client_id: String,
    /// FRP 协议版本
    pub version: String,
    /// 时间戳（毫秒），用于防重放
    pub timestamp: i64,
    /// 本次运行唯一标识
    pub run_id: String,
    /// 认证令牌
    pub token: String,
    /// 扩展元数据
    pub metas: std::collections::HashMap<String, String>,
    /// 客户端规范（可选）
    pub client_spec: Option<ClientSpec>,
}

/// 客户端规范 - 描述客户端类型和特性
///
/// # 字段说明
///
/// - `r#type`: 客户端类型（如 "frpc" 表示 frp 客户端）
/// - `always_auth_pass`: 是否始终需要认证
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientSpec {
    /// 客户端类型
    pub r#type: String,
    /// 是否始终需要认证
    pub always_auth_pass: bool,
}

/// 登录响应消息 - 服务器对客户端登录请求的响应
///
/// # 字段说明
///
/// - `version`: 服务器支持的协议版本
/// - `run_id`: 服务器生成的运行 ID
/// - `error`: 错误信息，若为空则表示登录成功
///
/// # 错误处理
///
/// 客户端收到响应后应检查 `error` 字段：
/// - 空字符串：登录成功
/// - 非空字符串：登录失败，error 包含失败原因
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginRespMsg {
    /// 服务器协议版本
    pub version: String,
    /// 服务器分配的运行 ID
    pub run_id: String,
    /// 错误信息（空表示成功）
    pub error: String,
}

/// 代理注册消息 - 客户端请求注册一个代理
///
/// # 字段说明
///
/// - `proxy`: 完整的代理配置，包括代理名称、类型、端口映射等
///
/// # 使用场景
///
/// 1. 客户端登录成功后自动注册所有配置的代理
/// 2. 客户端添加新代理时动态注册
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterProxyMsg {
    /// 代理配置
    pub proxy: rust_frp_config::ProxyConfig,
}

/// 代理注册响应消息 - 服务器对代理注册请求的响应
///
/// # 字段说明
///
/// - `name`: 注册的代理名称
/// - `error`: 错误信息（空表示成功）
///
/// # 常见错误
///
/// - "proxy already exists": 代理名称已被使用
/// - "port already in use": 所需端口已被占用
/// - "port not allowed": 端口不在允许范围内
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisterProxyRespMsg {
    /// 代理名称
    pub name: String,
    /// 错误信息（空表示成功）
    pub error: String,
}

/// 请求工作连接消息 - 服务器向客户端请求建立新的工作连接
///
/// # 消息流程
///
/// 当有用户请求访问某个代理时，服务器通过此消息通知客户端：
/// 1. 服务器收到外部请求访问特定代理
/// 2. 服务器向客户端发送 ReqWorkConnMsg
/// 3. 客户端建立新的工作连接并发送 NewWorkConnMsg
///
/// # 字段说明
///
/// - `proxy_name`: 需要建立连接的代理名称
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReqWorkConnMsg {
    /// 目标代理名称
    pub proxy_name: String,
}

/// 新工作连接消息 - 客户端通知服务器有新的工作连接可用
///
/// # 消息流程
///
/// ```text
/// Client                          Server
///   |                               |
///   |<-- ReqWorkConnMsg ------------|
///   |                               |
///   | [建立新的 TCP 连接]            |
///   |                               |
///   |--- NewWorkConnMsg ----------->|
///   |<-- StartWorkConnMsg ----------|
/// ```
///
/// # 字段说明
///
/// - `run_id`: 客户端运行 ID，用于验证客户端身份
/// - `proxy_name`: 此工作连接对应的代理名称
/// - `timestamp`: 时间戳（毫秒），用于防重放
/// - `sign_key`: HMAC 签名密钥，证明连接请求的合法性
/// - `use_encryption`: 是否对此连接启用端到端加密
/// - `use_compression`: 是否对此连接启用压缩
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewWorkConnMsg {
    /// 客户端运行 ID
    pub run_id: String,
    /// 代理名称
    pub proxy_name: String,
    /// 时间戳（毫秒）
    pub timestamp: i64,
    /// HMAC 签名密钥
    pub sign_key: String,
    /// 是否启用加密
    pub use_encryption: bool,
    /// 是否启用压缩
    pub use_compression: bool,
}

/// 开始工作连接消息 - 服务器响应新工作连接
///
/// # 字段说明
///
/// - `error`: 错误信息（空表示成功）
///
/// # 成功响应
///
/// 若连接建立成功，error 为空字符串。
/// 若连接建立失败，error 包含失败原因。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StartWorkConnMsg {
    /// 错误信息（空表示成功）
    pub error: String,
}

/// 新访问者连接消息 - 用于 TCP 打孔/反向代理访问
///
/// # 与 NewWorkConnMsg 的区别
///
/// - `NewWorkConnMsg`: 客户端主动建立连接，服务器使用此连接访问内网服务
/// - `NewVisitorConnMsg`: 外部用户通过服务器访问内网服务，服务器通知客户端
///
/// # 字段说明
///
/// - `run_id`: 客户端运行 ID
/// - `proxy_name`: 目标代理名称
/// - `timestamp`: 时间戳
/// - `sign_key`: HMAC 签名密钥
/// - `use_encryption`: 是否启用加密
/// - `use_compression`: 是否启用压缩
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewVisitorConnMsg {
    /// 客户端运行 ID
    pub run_id: String,
    /// 目标代理名称
    pub proxy_name: String,
    /// 时间戳（毫秒）
    pub timestamp: i64,
    /// HMAC 签名密钥
    pub sign_key: String,
    /// 是否启用加密
    pub use_encryption: bool,
    /// 是否启用压缩
    pub use_compression: bool,
}

/// 新访问者连接响应消息
///
/// # 字段说明
///
/// - `proxy_name`: 代理名称
/// - `error`: 错误信息（空表示成功）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewVisitorConnRespMsg {
    /// 代理名称
    pub proxy_name: String,
    /// 错误信息（空表示成功）
    pub error: String,
}

/// Ping 消息 - 客户端发送给服务器的心跳请求
///
/// # 心跳机制
///
/// 为检测连接存活状态，客户端定期发送 Ping 消息：
/// - 服务器收到 Ping 后回复 Pong
/// - 若一定时间内未收到响应，连接被认为已断开
///
/// # 字段说明
///
/// - `timestamp`: 发送时间戳（毫秒）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PingMsg {
    /// 时间戳（毫秒）
    pub timestamp: i64,
}

/// Pong 消息 - 服务器对心跳请求的响应
///
/// # 字段说明
///
/// - `timestamp`: 对应 Ping 消息的时间戳
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PongMsg {
    /// 时间戳（毫秒），回显 Ping 中的时间戳
    pub timestamp: i64,
}

/// 断开连接消息 - 通知对方关闭连接
///
/// # 字段说明
///
/// - `reason`: 断开原因
///
/// # 使用场景
///
/// - 服务器关闭时通知所有客户端
/// - 客户端关闭时通知服务器
/// - 认证失败时强制断开
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DisconnectMsg {
    /// 断开原因
    pub reason: String,
}

/// 代理状态消息 - 查询代理当前状态
///
/// # 字段说明
///
/// - `name`: 要查询的代理名称
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyStatusMsg {
    /// 代理名称
    pub name: String,
}

/// 代理状态响应消息 - 返回代理的当前状态
///
/// # 字段说明
///
/// - `name`: 代理名称
/// - `status`: 状态字符串（如 "running", "stopped"）
/// - `error`: 错误信息（若查询失败）
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyStatusRespMsg {
    /// 代理名称
    pub name: String,
    /// 当前状态
    pub status: String,
    /// 错误信息
    pub error: String,
}

/// 最大消息大小 - 10MB
///
/// # 安全考虑
///
/// 限制单条消息最大长度，防止：
/// - 内存耗尽攻击：恶意发送超大消息
/// - 整数溢出：消息长度字段被操纵
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// 从连接读取消息
///
/// # 协议格式
///
/// ```text
/// +--------+------------------------+
/// | 4字节  |      N 字节            |
/// | 长度   |      JSON 消息          |
/// | u32 BE |                        |
/// +--------+------------------------+
/// ```
///
/// # 参数
///
/// - `conn`: 实现 AsyncRead trait 的连接对象
///
/// # 返回值
///
/// - 成功：解析后的 Message 枚举
/// - 失败：Box<dyn Error> 错误
///
/// # 错误类型
///
/// - `InvalidData`: 消息长度超过 MAX_MESSAGE_SIZE
/// - `UnexpectedEof`: 连接提前关闭
/// - `Io`: 其他 I/O 错误
/// - `JSON`: JSON 解析错误
pub async fn read_message<T: AsyncRead + Unpin>(
    conn: &mut T,
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    // 读取 4 字节长度字段（大端序）
    let mut len_buf = [0; 4];
    conn.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // 安全检查：防止内存耗尽攻击
    if len > MAX_MESSAGE_SIZE {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "message size too large: {} bytes (max: {})",
                len, MAX_MESSAGE_SIZE
            ),
        )));
    }

    // 读取消息体
    let mut msg_buf = vec![0; len];
    conn.read_exact(&mut msg_buf).await?;

    // JSON 反序列化
    let msg: Message = serde_json::from_slice(&msg_buf)?;
    Ok(msg)
}

/// 向连接写入消息
///
/// # 协议格式
///
/// ```text
/// +--------+------------------------+
/// | 4字节  |      N 字节            |
/// | 长度   |      JSON 消息          |
/// | u32 BE |                        |
/// +--------+------------------------+
/// ```
///
/// # 参数
///
/// - `conn`: 实现 AsyncWrite trait 的连接对象
/// - `msg`: 要发送的消息引用
///
/// # 返回值
///
/// - 成功：()
/// - 失败：Box<dyn Error> 错误
pub async fn write_message<T: AsyncWrite + Unpin>(
    conn: &mut T,
    msg: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // JSON 序列化
    let msg_buf = serde_json::to_vec(msg)?;

    // 计算并写入长度（4 字节大端序）
    let len = msg_buf.len() as u32;
    let len_buf = len.to_be_bytes();
    conn.write_all(&len_buf).await?;

    // 写入消息体
    conn.write_all(&msg_buf).await?;
    Ok(())
}

/// 控制连接 - 用于客户端与服务器之间的控制平面通信
///
/// # 使用场景
///
/// 控制连接负责：
/// 1. 客户端认证（Login/LoginResp）
/// 2. 代理注册（RegisterProxy/Resp）
/// 3. 心跳保活（Ping/Pong）
/// 4. 工作连接协调（ReqWorkConn/NewWorkConn）
///
/// # 生命周期
///
/// ```text
/// 连接建立 -> 登录认证 -> 代理注册 -> 正常运行 -> 断开
/// ```
pub struct ControlConn {
    /// 底层连接（使用 trait object 支持多种传输）
    conn: Box<dyn FrpConn>,
}

impl ControlConn {
    /// 创建新的控制连接
    ///
    /// # 参数
    ///
    /// - `conn`: 实现了 FrpConn trait 的连接对象
    pub fn new(conn: Box<dyn FrpConn>) -> Self {
        Self { conn }
    }

    /// 异步读取消息
    pub async fn read_message(
        &mut self,
    ) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        read_message(&mut self.conn).await
    }

    /// 异步发送消息
    pub async fn write_message(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        write_message(&mut self.conn, msg).await
    }

    /// 发送原始字节数据
    ///
    /// # 使用场景
    ///
    /// 用于发送不适合 JSON 序列化的数据，如代理转发的原始流量
    pub async fn write_all(
        &mut self,
        buf: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.conn.write_all(buf).await?;
        Ok(())
    }

    /// 获取远程地址
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.conn.remote_addr()
    }
}

/// 工作连接 - 用于实际代理流量的传输
///
/// # 与控制连接的区别
///
/// | 特性 | 控制连接 | 工作连接 |
/// |------|---------|---------|
/// | 用途 | 协议控制 | 流量转发 |
/// | 数量 | 1:1 | N:M |
/// | 生命周期 | 长连接 | 按需创建 |
///
/// # 使用场景
///
/// 工作连接负责：
/// 1. 代理流量的双向传输
/// 2. 可能启用端到端加密
/// 3. 可能启用数据压缩
pub struct WorkConn {
    /// 底层连接
    conn: Box<dyn FrpConn>,
    /// 此连接关联的代理名称
    proxy_name: String,
}

impl WorkConn {
    /// 创建新的工作连接
    ///
    /// # 参数
    ///
    /// - `conn`: 底层连接
    /// - `proxy_name`: 关联的代理名称
    pub fn new(conn: Box<dyn FrpConn>, proxy_name: String) -> Self {
        Self { conn, proxy_name }
    }

    /// 获取关联的代理名称
    pub fn proxy_name(&self) -> &str {
        &self.proxy_name
    }

    /// 获取远程地址
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.conn.remote_addr()
    }
}

/// 代理管理器 trait - 定义代理管理接口
///
/// # 实现者
///
/// - 客户端实现：管理本地代理配置
/// - 服务器实现：管理注册的代理
///
/// # 主要操作
///
/// - 添加代理
/// - 移除代理
/// - 查询代理状态
#[async_trait::async_trait]
pub trait ProxyManager {
    /// 添加代理
    ///
    /// # 参数
    ///
    /// - `config`: 代理配置
    async fn add_proxy(
        &self,
        config: rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 移除代理
    ///
    /// # 参数
    ///
    /// - `name`: 代理名称
    async fn remove_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 获取代理状态
    ///
    /// # 参数
    ///
    /// - `name`: 代理名称
    ///
    /// # 返回值
    ///
    /// - `Some(status)`: 代理状态字符串
    /// - `None`: 代理不存在
    async fn get_proxy_status(
        &self,
        name: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>;

    /// 清除所有代理（用于重连时重置状态）
    async fn clear(&self);
}

/// 访问者管理器 trait - 定义访问者连接管理接口
///
/// # 访问者 vs 代理
///
/// - **代理 (Proxy)**: 客户端暴露本地服务给外部访问
/// - **访问者 (Visitor)**: 客户端通过服务器访问其他客户端的服务
///
/// # TCP 打孔机制
///
/// 访问者通过 NewVisitorConnMsg 消息请求连接，服务器协调建立双向连接。
#[async_trait::async_trait]
pub trait VisitorManager {
    /// 添加访问者
    async fn add_visitor(
        &self,
        config: rust_frp_config::VisitorConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 移除访问者
    async fn remove_visitor(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 清除所有访问者（用于重连时重置状态）
    async fn clear(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_msg_serialization() {
        let msg = LoginMsg {
            arch: "amd64".to_string(),
            os: "linux".to_string(),
            hostname: "test-host".to_string(),
            pool_count: 10,
            user: "admin".to_string(),
            client_id: "client-001".to_string(),
            version: "1.0.0".to_string(),
            timestamp: 1234567890,
            run_id: "run-abc".to_string(),
            token: "secret".to_string(),
            metas: std::collections::HashMap::new(),
            client_spec: Some(ClientSpec {
                r#type: "frpc".to_string(),
                always_auth_pass: true,
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: LoginMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.arch, "amd64");
        assert_eq!(deserialized.hostname, "test-host");
        assert_eq!(deserialized.token, "secret");
    }

    #[test]
    fn test_login_resp_msg_serialization() {
        let msg = LoginRespMsg {
            version: "1.0.0".to_string(),
            run_id: "server-run-001".to_string(),
            error: "".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: LoginRespMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.version, "1.0.0");
        assert_eq!(deserialized.error, "");
    }

    #[test]
    fn test_register_proxy_msg_serialization() {
        let proxy_config = rust_frp_config::ProxyConfig {
            name: "test-proxy".to_string(),
            r#type: "tcp".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_port: Some(9302),
            ..Default::default()
        };
        let msg = RegisterProxyMsg {
            proxy: proxy_config,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: RegisterProxyMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proxy.name, "test-proxy");
    }

    #[test]
    fn test_message_enum_serialization() {
        let login = Message::Login(LoginMsg {
            arch: "amd64".to_string(),
            os: "linux".to_string(),
            hostname: "h1".to_string(),
            pool_count: 10,
            user: "u1".to_string(),
            client_id: "c1".to_string(),
            version: "1.0".to_string(),
            timestamp: 1000,
            run_id: "r1".to_string(),
            token: "t1".to_string(),
            metas: std::collections::HashMap::new(),
            client_spec: None,
        });
        let json = serde_json::to_string(&login).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();
        match deserialized {
            Message::Login(lm) => {
                assert_eq!(lm.hostname, "h1");
                assert_eq!(lm.token, "t1");
            }
            _ => panic!("Expected Login variant"),
        }
    }

    #[test]
    fn test_ping_pong_serialization() {
        let ping = Message::Ping(PingMsg { timestamp: 999 });
        let json = serde_json::to_string(&ping).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();
        match deserialized {
            Message::Ping(p) => assert_eq!(p.timestamp, 999),
            _ => panic!("Expected Ping variant"),
        }
    }

    #[test]
    fn test_disconnect_msg_serialization() {
        let msg = DisconnectMsg {
            reason: "server shutting down".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: DisconnectMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.reason, "server shutting down");
    }

    #[test]
    fn test_register_proxy_resp_msg() {
        let msg = RegisterProxyRespMsg {
            name: "proxy-1".to_string(),
            error: "port already in use".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: RegisterProxyRespMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "proxy-1");
        assert_eq!(deserialized.error, "port already in use");
    }

    #[test]
    fn test_req_work_conn_msg() {
        let msg = ReqWorkConnMsg {
            proxy_name: "ssh".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ReqWorkConnMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proxy_name, "ssh");
    }

    #[test]
    fn test_start_work_conn_msg() {
        let success = StartWorkConnMsg { error: "".to_string() };
        let json = serde_json::to_string(&success).unwrap();
        let deserialized: StartWorkConnMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.error, "");

        let fail = StartWorkConnMsg { error: "connection refused".to_string() };
        let json = serde_json::to_string(&fail).unwrap();
        let deserialized: StartWorkConnMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.error, "connection refused");
    }

    #[test]
    fn test_proxy_status_msg() {
        let msg = ProxyStatusMsg { name: "web".to_string() };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ProxyStatusMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "web");
    }

    #[tokio::test]
    async fn test_read_write_message_roundtrip() {
        let msg = Message::Ping(PingMsg { timestamp: 12345 });
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();
        let deserialized = read_message(&mut buf.as_slice()).await.unwrap();
        match deserialized {
            Message::Ping(p) => assert_eq!(p.timestamp, 12345),
            _ => panic!("Expected Ping"),
        }
    }

    #[tokio::test]
    async fn test_read_write_message_login_roundtrip() {
        let msg = Message::Login(LoginMsg {
            arch: "amd64".to_string(),
            os: "linux".to_string(),
            hostname: "h1".to_string(),
            pool_count: 10,
            user: "admin".to_string(),
            client_id: "c1".to_string(),
            version: "1.0".to_string(),
            timestamp: 1000,
            run_id: "r1".to_string(),
            token: "secret".to_string(),
            metas: std::collections::HashMap::new(),
            client_spec: None,
        });
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();
        let deserialized = read_message(&mut buf.as_slice()).await.unwrap();
        match deserialized {
            Message::Login(lm) => {
                assert_eq!(lm.hostname, "h1");
                assert_eq!(lm.token, "secret");
            }
            _ => panic!("Expected Login"),
        }
    }

    #[test]
    fn test_max_message_size_constant() {
        assert_eq!(MAX_MESSAGE_SIZE, 10 * 1024 * 1024);
    }
}
