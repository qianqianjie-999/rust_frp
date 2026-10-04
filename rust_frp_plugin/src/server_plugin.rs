//! 服务端 HTTP 插件机制（对齐原版 frp `pkg/plugin/server`）
//!
//! frps 在处理**控制面事件**时，向配置的 HTTP 服务发起同步回调，由外部
//! 服务决定放行/拒绝，或返回修改后的内容。与 [`crate`] 中的本地插件
//! （unix_socket / static_file 等，作用于数据面）互补。
//!
//! # 支持的回调操作
//!
//! | op | 触发时机 | 可拒绝 | 可改写内容 |
//! |----|----------|:------:|:----------:|
//! | `Login` | 客户端登录鉴权后 | ✅ | ✅（如注入 metadata） |
//! | `NewProxy` | 客户端注册代理时 | ✅ | ✅（如改写代理配置） |
//! | `CloseProxy` | 代理被移除时 | ❌（仅通知） | ❌ |
//! | `Ping` | 收到客户端心跳时 | ✅ | ✅ |
//! | `NewWorkConn` | 工作连接建立时 | ✅ | ✅ |
//! | `NewUserConn` | 外部用户连接到达时 | ✅ | ❌ |
//!
//! # 回调协议
//!
//! 请求：`POST {addr}{path}?version=0.1.0&op={Op}`
//!
//! ```http
//! Content-Type: application/json
//! X-Frp-Reqid: <random hex>
//!
//! {"version":"0.1.0","op":"Login","content":{...}}
//! ```
//!
//! 响应（HTTP 200 + JSON）：
//!
//! ```json
//! {"reject":false,"reject_reason":"","unchange":true,"content":null}
//! ```
//!
//! - `reject = true`：本次操作被拒绝，`reject_reason` 回传客户端；
//! - `unchange = false`：采用 `content` 覆写原始内容。
//!
//! # 失败语义
//!
//! 回调**网络/协议失败**与**显式拒绝**对调用方都是「操作失败」（fail-closed），
//! 由调用方决定后续处理（登录失败则断开、注册失败则回执错误）。`CloseProxy`
//! 是单向通知，失败只记日志，不影响主流程。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// 插件回调协议版本
pub const API_VERSION: &str = "0.1.0";

/// 插件常见操作名（与 [`rust_frp_config::VALID_PLUGIN_OPS`] 一致）
pub const OP_LOGIN: &str = "Login";
pub const OP_NEW_PROXY: &str = "NewProxy";
pub const OP_CLOSE_PROXY: &str = "CloseProxy";
pub const OP_PING: &str = "Ping";
pub const OP_NEW_WORK_CONN: &str = "NewWorkConn";
pub const OP_NEW_USER_CONN: &str = "NewUserConn";

/// 单次回调超时：插件无响应不应拖垮 frps 控制面
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(10);

/// 插件请求体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    /// 协议版本
    pub version: String,
    /// 操作名
    pub op: String,
    /// 事件内容
    pub content: Value,
}

/// 插件响应体
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginResponse {
    /// 是否拒绝本次操作
    #[serde(default)]
    pub reject: bool,
    /// 拒绝原因（`reject = true` 时作为错误信息回传）
    #[serde(default)]
    pub reject_reason: String,
    /// 是否保持内容不变（`false` 表示采用 `content` 覆写）
    #[serde(default)]
    pub unchange: bool,
    /// 覆写后的内容
    #[serde(default)]
    pub content: Option<Value>,
}

/// 单个 HTTP 插件
#[derive(Debug, Clone)]
struct HttpPlugin {
    name: String,
    /// 完整回调 URL（`addr` + `path`），未带 scheme 时按 `http://` 处理
    url: String,
    /// `https://` 地址是否校验服务端证书
    tls_verify: bool,
}

impl HttpPlugin {
    fn new(cfg: &rust_frp_config::HttpPluginConfig) -> Self {
        let addr = cfg.addr.trim().trim_end_matches('/');
        let normalized = if addr.starts_with("http://") || addr.starts_with("https://") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        // path 为空或未以 '/' 开头时规范化，避免拼出 "host:porthandler" 这类非法 URL
        let path = cfg.path.trim();
        let path = if path.is_empty() {
            String::new()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Self {
            name: cfg.name.clone(),
            url: format!("{normalized}{path}"),
            tls_verify: cfg.tls_verify,
        }
    }

    async fn handle(
        &self,
        op: &str,
        content: &Value,
        req_id: &str,
    ) -> Result<PluginResponse, String> {
        let request = PluginRequest {
            version: API_VERSION.to_string(),
            op: op.to_string(),
            content: content.clone(),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|e| format!("failed to encode plugin request: {e}"))?;
        // 回调地址可能已带 query（如 addr 写成 http://h:9000/x?a=1），
        // 此时用 & 追加，避免出现两个 ?
        let sep = if self.url.contains('?') { '&' } else { '?' };
        let url = format!("{}{}version={}&op={}", self.url, sep, API_VERSION, op);

        let opts = rust_frp_net::http::HttpOptions {
            tls_verify: self.tls_verify,
            ca_file: None,
            timeout: CALLBACK_TIMEOUT,
        };
        let resp =
            rust_frp_net::http::post_json(&url, &body, &[("X-Frp-Reqid", req_id)], &opts).await?;
        if !resp.is_success() {
            return Err(format!(
                "plugin [{}] returned HTTP {}: {}",
                self.name,
                resp.status,
                resp.body.trim()
            ));
        }
        serde_json::from_str::<PluginResponse>(&resp.body)
            .map_err(|e| format!("invalid plugin response JSON: {e}"))
    }
}

/// 服务端插件管理器
///
/// 按操作类型分桶持有插件；`from_configs` 在启动时构建一次，之后只读。
#[derive(Debug, Clone, Default)]
pub struct Manager {
    login: Vec<HttpPlugin>,
    new_proxy: Vec<HttpPlugin>,
    close_proxy: Vec<HttpPlugin>,
    ping: Vec<HttpPlugin>,
    new_work_conn: Vec<HttpPlugin>,
    new_user_conn: Vec<HttpPlugin>,
}

impl Manager {
    /// 按配置构建，并打印未识别 op 的告警（配置校验已在 config 层拦截，此处兜底）。
    pub fn from_configs(configs: &[rust_frp_config::HttpPluginConfig]) -> Self {
        let mut m = Self::default();
        for cfg in configs {
            let plugin = HttpPlugin::new(cfg);
            for op in &cfg.ops {
                match op.as_str() {
                    OP_LOGIN => m.login.push(plugin.clone()),
                    OP_NEW_PROXY => m.new_proxy.push(plugin.clone()),
                    OP_CLOSE_PROXY => m.close_proxy.push(plugin.clone()),
                    OP_PING => m.ping.push(plugin.clone()),
                    OP_NEW_WORK_CONN => m.new_work_conn.push(plugin.clone()),
                    OP_NEW_USER_CONN => m.new_user_conn.push(plugin.clone()),
                    other => log::warn!(
                        "http plugin [{}] subscribes to unknown op [{}], ignored",
                        cfg.name,
                        other
                    ),
                }
            }
        }
        log::info!(
            "server http plugin manager initialized: {} plugin(s) \
             (Login={}, NewProxy={}, CloseProxy={}, Ping={}, NewWorkConn={}, NewUserConn={})",
            configs.len(),
            m.login.len(),
            m.new_proxy.len(),
            m.close_proxy.len(),
            m.ping.len(),
            m.new_work_conn.len(),
            m.new_user_conn.len(),
        );
        m
    }

    /// 是否没有任何插件（调用方可据此跳过回调）
    pub fn is_empty(&self) -> bool {
        self.login.is_empty()
            && self.new_proxy.is_empty()
            && self.close_proxy.is_empty()
            && self.ping.is_empty()
            && self.new_work_conn.is_empty()
            && self.new_user_conn.is_empty()
    }

    /// 登录回调：插件可拒绝登录或覆写登录内容
    pub async fn login(&self, content: &mut Value) -> Result<(), String> {
        Self::handle_mutable(&self.login, OP_LOGIN, content).await
    }

    /// 新建代理回调：插件可拒绝注册或覆写代理配置
    pub async fn new_proxy(&self, content: &mut Value) -> Result<(), String> {
        Self::handle_mutable(&self.new_proxy, OP_NEW_PROXY, content).await
    }

    /// 关闭代理通知：失败只记日志，不影响调用方
    pub async fn close_proxy(&self, content: &Value) {
        if self.close_proxy.is_empty() {
            return;
        }
        let req_id = new_req_id();
        for plugin in &self.close_proxy {
            if let Err(e) = plugin.handle(OP_CLOSE_PROXY, content, &req_id).await {
                log::warn!(
                    "send CloseProxy request to plugin [{}] error: {}",
                    plugin.name,
                    e
                );
            }
        }
    }

    /// 心跳回调：插件可拒绝心跳或覆写心跳内容
    pub async fn ping(&self, content: &mut Value) -> Result<(), String> {
        Self::handle_mutable(&self.ping, OP_PING, content).await
    }

    /// 工作连接回调：插件可拒绝工作连接
    pub async fn new_work_conn(&self, content: &mut Value) -> Result<(), String> {
        Self::handle_mutable(&self.new_work_conn, OP_NEW_WORK_CONN, content).await
    }

    /// 用户连接回调：插件可拒绝本次外部接入
    pub async fn new_user_conn(&self, content: &Value) -> Result<(), String> {
        if self.new_user_conn.is_empty() {
            return Ok(());
        }
        let req_id = new_req_id();
        for plugin in &self.new_user_conn {
            let resp = plugin
                .handle(OP_NEW_USER_CONN, content, &req_id)
                .await
                .map_err(|e| {
                    format!(
                        "send NewUserConn request to plugin [{}] error: {}",
                        plugin.name, e
                    )
                })?;
            if resp.reject {
                return Err(reject_reason(&plugin.name, OP_NEW_USER_CONN, &resp));
            }
        }
        Ok(())
    }

    /// 可变内容回调的通用流程：顺序调用所有插件，任一拒绝即中止。
    async fn handle_mutable(
        plugins: &[HttpPlugin],
        op: &str,
        content: &mut Value,
    ) -> Result<(), String> {
        if plugins.is_empty() {
            return Ok(());
        }
        let req_id = new_req_id();
        for plugin in plugins {
            let resp = plugin
                .handle(op, content, &req_id)
                .await
                .map_err(|e| format!("send {op} request to plugin [{}] error: {e}", plugin.name))?;
            if resp.reject {
                return Err(reject_reason(&plugin.name, op, &resp));
            }
            if !resp.unchange {
                if let Some(new_content) = resp.content {
                    *content = new_content;
                }
            }
        }
        Ok(())
    }
}

fn reject_reason(plugin_name: &str, op: &str, resp: &PluginResponse) -> String {
    if resp.reject_reason.trim().is_empty() {
        format!("{op} rejected by plugin [{plugin_name}]")
    } else {
        resp.reject_reason.clone()
    }
}

/// 生成随机 reqid（16 位 hex），用于插件侧日志关联
fn new_req_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 8];
    if SystemRandom::new().fill(&mut buf).is_err() {
        // 退化路径：时间戳 + 进程内计数器
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        return format!("{:08x}{:08x}", ts as u32, n as u32);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg(name: &str, addr: &str, path: &str, ops: &[&str]) -> rust_frp_config::HttpPluginConfig {
        rust_frp_config::HttpPluginConfig {
            name: name.to_string(),
            addr: addr.to_string(),
            path: path.to_string(),
            ops: ops.iter().map(|s| s.to_string()).collect(),
            tls_verify: false,
        }
    }

    /// 起一个一次性插件服务端：读取一份请求，按固定响应回写。
    /// 返回 (端口, 收到的请求原文句柄)。
    async fn spawn_plugin(
        status_line: &'static str,
        body: &'static str,
    ) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (port, handle)
    }

    #[tokio::test]
    async fn test_plugin_handle_roundtrip_and_request_shape() {
        let (port, handle) = spawn_plugin(
            "HTTP/1.1 200 OK",
            r#"{"reject":false,"unchange":true,"reject_reason":"","content":null}"#,
        )
        .await;
        let plugin = HttpPlugin::new(&cfg(
            "p1",
            &format!("127.0.0.1:{port}"),
            "/handler",
            &[OP_LOGIN],
        ));
        let content = serde_json::json!({"user": "alice"});
        let resp = plugin.handle(OP_LOGIN, &content, "deadbeef").await.unwrap();
        assert!(!resp.reject);

        let req = handle.await.unwrap();
        // 请求行 + query 携带 version/op；X-Frp-Reqid 头存在；body 为 JSON
        assert!(
            req.starts_with("POST /handler?version=0.1.0&op=Login HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("X-Frp-Reqid: deadbeef"));
        assert!(req.contains("\"op\":\"Login\""));
        assert!(req.contains("\"user\":\"alice\""));
    }

    #[tokio::test]
    async fn test_manager_login_reject_returns_reason() {
        let (port, _handle) = spawn_plugin(
            "HTTP/1.1 200 OK",
            r#"{"reject":true,"reject_reason":"bad user","unchange":true}"#,
        )
        .await;
        let m =
            Manager::from_configs(&[cfg("auth", &format!("127.0.0.1:{port}"), "", &[OP_LOGIN])]);
        let mut content = serde_json::json!({"user": "bob"});
        let err = m.login(&mut content).await.unwrap_err();
        assert_eq!(err, "bad user");
    }

    #[tokio::test]
    async fn test_manager_login_unchange_false_overwrites_content() {
        let (port, _handle) = spawn_plugin(
            "HTTP/1.1 200 OK",
            r#"{"reject":false,"unchange":false,"content":{"user":"bob","metas":{"role":"admin"}}}"#,
        )
        .await;
        let m =
            Manager::from_configs(&[cfg("meta", &format!("127.0.0.1:{port}"), "", &[OP_LOGIN])]);
        let mut content = serde_json::json!({"user": "bob"});
        m.login(&mut content).await.unwrap();
        assert_eq!(content["metas"]["role"], "admin");
    }

    #[tokio::test]
    async fn test_manager_no_plugins_is_noop() {
        let m = Manager::from_configs(&[]);
        assert!(m.is_empty());
        let mut content = serde_json::json!({});
        assert!(m.login(&mut content).await.is_ok());
        // 未订阅 NewUserConn 的插件不会拦截
        assert!(m.new_user_conn(&content).await.is_ok());
    }

    #[tokio::test]
    async fn test_manager_new_user_conn_reject() {
        let (port, _handle) = spawn_plugin(
            "HTTP/1.1 200 OK",
            r#"{"reject":true,"reject_reason":"blocked by policy"}"#,
        )
        .await;
        let m = Manager::from_configs(&[cfg(
            "guard",
            &format!("127.0.0.1:{port}"),
            "",
            &[OP_NEW_USER_CONN],
        )]);
        let content = serde_json::json!({"proxy_name": "web", "remote_addr": "1.2.3.4:5"});
        assert_eq!(
            m.new_user_conn(&content).await.unwrap_err(),
            "blocked by policy"
        );
        // 该插件未订阅 Login，不应被调用（无第二条连接可用，若调用会失败）
        let mut c = serde_json::json!({});
        assert!(m.login(&mut c).await.is_ok());
    }

    #[tokio::test]
    async fn test_manager_close_proxy_failure_is_swallowed() {
        // 指向一个不会有人监听的端口 → 回调必然失败，但 close_proxy 不返回错误
        let m = Manager::from_configs(&[cfg("notify", "127.0.0.1:1", "", &[OP_CLOSE_PROXY])]);
        m.close_proxy(&serde_json::json!({"proxy_name": "p"})).await;
    }
}
