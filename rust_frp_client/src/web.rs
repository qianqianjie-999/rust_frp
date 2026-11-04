//! 从 lib.rs 拆出的 web 实现。

use super::*;

/// Web 服务器（frpc 管理 API）
///
/// 路由：
/// - `GET  /health`   存活探针
/// - `GET  /proxies`  代理配置列表
/// - `GET  /visitors` 访客配置列表
/// - `GET  /status`   代理/访客运行状态（`frpc status` 使用）
/// - `POST /stop`     触发客户端优雅退出（`frpc stop` 使用）
/// - `POST /reload`   触发配置热重载（`frpc reload` 使用）
/// - `GET  /config`   读取配置文件原文（对齐原版 `GET /api/config`）
/// - `PUT  /config`   校验并原子覆写配置文件 + 触发热重载（对齐原版 `PUT /api/config`）
///
/// 配置了 `webServer.user` + `webServer.password` 时全部端点要求
/// Basic 认证（常量时间比较）；未配置则保持开放（向后兼容）。
/// `/config` 读写端点因涉及 token 等敏感内容与配置文件覆写，在未配置
/// 认证时直接 403 禁用（fail-closed）。
pub struct WebServer {
    addr: SocketAddr,
    /// Basic 认证凭据（user, password），None 表示不启用
    auth: Option<(String, String)>,
    server: Option<tokio::task::JoinHandle<()>>,
}

/// Web 服务器共享状态
#[derive(Clone)]
pub(super) struct WebServerState {
    pub(super) proxy_manager: Arc<ClientProxyManager>,
    pub(super) visitor_manager: Arc<ClientVisitorManager>,
    /// reload 端点通过该 Notify 通知 Client 主循环执行 reload_config
    pub(super) reload_notify: Arc<tokio::sync::Notify>,
    /// stop 端点通过该 Notify 通知 Client 主循环优雅退出
    pub(super) stop_notify: Arc<tokio::sync::Notify>,
    /// 配置文件路径（PUT /config 原子落盘的目标；None 表示管理端不可用）
    pub(super) config_path: Option<String>,
    /// webServer 是否配置了 user/password（config 端点在 false 时直接 403）
    pub(super) auth_enabled: bool,
}

impl WebServer {
    pub fn new(
        config: &rust_frp_config::WebServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        // user/password 必须成对配置才启用 Basic 认证；只配一个视为未配置
        let auth = match (config.user.as_deref(), config.password.as_deref()) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                Some((u.to_string(), p.to_string()))
            }
            _ => None,
        };
        Ok(Self {
            addr,
            auth,
            server: None,
        })
    }

    pub async fn start(&mut self, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(WebServerState {
            proxy_manager: client.proxy_manager.clone(),
            visitor_manager: client.visitor_manager.clone(),
            reload_notify: client.reload_notify.clone(),
            stop_notify: client.stop_notify.clone(),
            config_path: client.config_path.clone(),
            auth_enabled: self.auth.is_some(),
        });

        let auth = self.auth.clone();
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/proxies", get(proxies_handler))
            .route("/visitors", get(visitors_handler))
            .route("/status", get(status_handler))
            .route("/stop", post(stop_handler))
            .route("/reload", post(reload_handler))
            .route("/config", get(get_config_handler).put(put_config_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                basic_auth_middleware(req, next, auth.clone())
            }));

        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("Web server error: {:?}", e);
            }
        });
        self.server = Some(handle);

        Ok(())
    }
}

/// Basic 认证中间件：未配置凭据直接放行；配置后校验（常量时间比较）
pub(super) async fn basic_auth_middleware(
    req: Request,
    next: Next,
    expected: Option<(String, String)>,
) -> Response {
    let Some((user, password)) = expected else {
        return next.run(req).await;
    };

    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_basic_credentials)
        .map(|(u, p)| {
            rust_frp_auth::constant_time_compare(u.as_bytes(), user.as_bytes())
                && rust_frp_auth::constant_time_compare(p.as_bytes(), password.as_bytes())
        })
        .unwrap_or(false);

    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"frpc admin\"")],
        )
            .into_response()
    }
}

/// 解析 `Authorization: Basic <base64(user:password)>` 头
pub(super) fn parse_basic_credentials(value: &str) -> Option<(String, String)> {
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

pub(super) async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "timestamp": get_timestamp(),
    }))
}

pub(super) async fn proxies_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<Vec<rust_frp_config::ProxyConfig>> {
    let proxies = state.proxy_manager.proxies.read().await;
    Json(proxies.values().cloned().collect())
}

pub(super) async fn visitors_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<Vec<rust_frp_config::VisitorConfig>> {
    let visitors = state.visitor_manager.visitors.read().await;
    Json(visitors.values().cloned().collect())
}

/// `GET /status`：代理/访客运行状态（对齐 frp 原版 `frpc status` 的语义）
pub(super) async fn status_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<serde_json::Value> {
    let proxies = state.proxy_manager.proxies.read().await;
    let proxy_names: Vec<(String, String, u16, Option<u16>)> = proxies
        .values()
        .map(|p| {
            (
                p.name.clone(),
                p.r#type.clone(),
                p.local_port,
                p.remote_port,
            )
        })
        .collect();
    drop(proxies);

    let mut proxy_list: Vec<serde_json::Value> = Vec::with_capacity(proxy_names.len());
    for (name, proxy_type, local_port, remote_port) in proxy_names {
        // 累计流量（客户端视角）：down = 服务端→本地，up = 本地→服务端
        let (bytes_down, bytes_up) = state
            .proxy_manager
            .traffic_snapshot(&name)
            .await
            .unwrap_or((0, 0));
        proxy_list.push(serde_json::json!({
            "name": name,
            "type": proxy_type,
            "status": "running",
            "local_port": local_port,
            "remote_port": remote_port,
            "traffic_down": bytes_down,
            "traffic_up": bytes_up,
        }));
    }

    let visitors = state.visitor_manager.visitors.read().await;
    let visitor_list: Vec<serde_json::Value> = visitors
        .values()
        .map(|v| {
            serde_json::json!({
                "name": v.name,
                "type": v.r#type,
                "server_name": v.server_name,
                "status": "running",
            })
        })
        .collect();
    drop(visitors);

    Json(serde_json::json!({
        "proxies": proxy_list,
        "visitors": visitor_list,
    }))
}

/// `POST /reload`：通知 Client 主循环重读配置并重新注册代理/访客。
///
/// 通知是异步投递（Notify 许可位语义），端点返回时 reload 尚未完成，
/// 与 frp 原版同步等待 reload 结束的语义略有差异。
pub(super) async fn reload_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<serde_json::Value> {
    state.reload_notify.notify_one();
    Json(serde_json::json!({
        "msg": "reload signal sent",
        "code": 200,
    }))
}

/// `POST /stop`：通知 Client 主循环优雅退出（对齐原版 `POST /api/stop`）。
///
/// 与 `/reload` 同为异步投递：端点返回时退出流程刚被唤醒，
/// 客户端会先向服务端发送 Disconnect 再排空存量连接后退出。
pub(super) async fn stop_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<serde_json::Value> {
    state.stop_notify.notify_one();
    Json(serde_json::json!({
        "msg": "stop signal sent",
        "code": 200,
    }))
}

/// config 端点的前置守卫：未启用认证或未提供配置路径时拒绝
pub(super) fn config_endpoint_guard(state: &WebServerState) -> Result<String, Box<Response>> {
    if !state.auth_enabled {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "config API is disabled: configure webServer.user/password first \
                 (config content contains auth token)"
                    .to_string(),
            )
                .into_response(),
        ));
    }
    let Some(path) = state.config_path.clone() else {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "config API is unavailable: frpc was started without a config file path"
                    .to_string(),
            )
                .into_response(),
        ));
    };
    Ok(path)
}

/// `GET /config`：返回配置文件原文（text/plain）
pub(super) async fn get_config_handler(State(state): State<Arc<WebServerState>>) -> Response {
    let path = match config_endpoint_guard(&state) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            content,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read config failed: {e}"),
        )
            .into_response(),
    }
}

/// `PUT /config`：校验请求体为新配置 → 原子覆写配置文件 → 触发热重载。
///
/// 语义对齐原版 frp 的 `PUT /api/config`：写盘成功即返回 200，重载由
/// reload 通道异步完成；校验失败返回 400 且不落盘（原文件保持不动）。
pub(super) async fn put_config_handler(
    State(state): State<Arc<WebServerState>>,
    body: String,
) -> Response {
    let path = match config_endpoint_guard(&state) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    // 先整体校验（解析 + 归并 + 规则校验），失败不落盘
    if let Err(e) = rust_frp_config::ConfigLoader::validate_client_config_content(&body) {
        return (
            StatusCode::BAD_REQUEST,
            format!("config validation failed: {e}"),
        )
            .into_response();
    }

    // 原子写：临时文件 + rename，避免写一半崩溃留下残缺配置
    let tmp_path = format!("{}.tmp-{}", path, rand_id(8));
    if let Err(e) = tokio::fs::write(&tmp_path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write config failed: {e}"),
        )
            .into_response();
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &path).await {
        // rename 失败时清理临时文件，避免残留
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rename config failed: {e}"),
        )
            .into_response();
    }

    log::info!("config updated via admin API, triggering reload");
    state.reload_notify.notify_one();
    Json(serde_json::json!({
        "msg": "config updated, reload triggered",
        "code": 200,
    }))
    .into_response()
}

/// 健康检查器
///
/// 定期检查后端服务健康状态，支持 TCP 和 HTTP 两种检查方式。
pub struct HealthChecker {
    config: rust_frp_config::ProxyConfig,
}

impl HealthChecker {
    pub fn new(config: rust_frp_config::ProxyConfig) -> Self {
        Self { config }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let hc = self.config.health_check.as_ref();
            let hc = match hc {
                Some(c) => c,
                None => return,
            };

            let interval = tokio::time::Duration::from_secs(hc.interval_seconds.max(1) as u64);
            let timeout = tokio::time::Duration::from_secs(hc.timeout_seconds.max(1) as u64);
            let max_failed = hc.max_failed;
            let check_type = hc.r#type.clone();
            let path = hc.path.clone();
            let target_addr = format!("{}:{}", self.config.local_ip, self.config.local_port);
            let mut failed_count: u32 = 0;

            loop {
                tokio::time::sleep(interval).await;

                match check_type.as_str() {
                    "tcp" => {
                        let result = tokio::time::timeout(
                            timeout,
                            tokio::net::TcpStream::connect(&target_addr),
                        )
                        .await;
                        match result {
                            Ok(Ok(_)) => {
                                if failed_count > 0 {
                                    log::warn!(
                                        "Health check for proxy '{}' recovered (TCP: {})",
                                        self.config.name,
                                        target_addr
                                    );
                                }
                                failed_count = 0;
                            }
                            _ => {
                                failed_count += 1;
                                log::warn!(
                                    "Health check for proxy '{}' failed ({}/{}): TCP connect to {}",
                                    self.config.name,
                                    failed_count,
                                    max_failed,
                                    target_addr
                                );
                                if failed_count >= max_failed {
                                    log::error!(
                                        "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                        self.config.name
                                    );
                                    failed_count = 0;
                                }
                            }
                        }
                    }
                    "http" => {
                        let path = path.clone().unwrap_or_else(|| "/".to_string());
                        let result = tokio::time::timeout(timeout, async {
                            let stream = tokio::net::TcpStream::connect(&target_addr).await?;
                            let (mut reader, mut writer) =
                                tokio::io::split(tokio::io::BufStream::new(stream));
                            use tokio::io::AsyncReadExt;
                            use tokio::io::AsyncWriteExt;

                            let request = format!(
                                "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                                path, self.config.local_ip
                            );
                            writer.write_all(request.as_bytes()).await?;

                            let mut response = String::new();
                            reader.read_to_string(&mut response).await?;

                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response)
                        })
                        .await;

                        match result {
                            Ok(Ok(response)) => {
                                if response.contains("200 OK") || response.contains("HTTP/1.") {
                                    if failed_count > 0 {
                                        log::warn!(
                                            "Health check for proxy '{}' recovered (HTTP: {})",
                                            self.config.name,
                                            target_addr
                                        );
                                    }
                                    failed_count = 0;
                                } else {
                                    failed_count += 1;
                                    log::warn!(
                                        "Health check for proxy '{}' failed ({}/{}): HTTP unexpected response",
                                        self.config.name, failed_count, max_failed
                                    );
                                    if failed_count >= max_failed {
                                        log::error!(
                                            "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                            self.config.name
                                        );
                                        failed_count = 0;
                                    }
                                }
                            }
                            _ => {
                                failed_count += 1;
                                log::warn!(
                                    "Health check for proxy '{}' failed ({}/{}): HTTP request to {}",
                                    self.config.name, failed_count, max_failed, target_addr
                                );
                                if failed_count >= max_failed {
                                    log::error!(
                                        "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                        self.config.name
                                    );
                                    failed_count = 0;
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!(
                            "Unsupported health check type '{}' for proxy '{}'",
                            check_type,
                            self.config.name
                        );
                        break;
                    }
                }
            }
        })
    }
}
