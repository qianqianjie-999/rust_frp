//! Web 管理端：会话鉴权、防爆破、路由与 axum 服务

use axum::extract::State;
use axum::response::IntoResponse;
use rust_frp_util::get_timestamp;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::*;

/// 管理端会话有效期（默认 8 小时）
const WEB_SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

/// 管理端会话 cookie 名称
pub(crate) const WEB_SESSION_COOKIE: &str = "frp_session";

/// 常量时间字符串比较，避免凭据/签名比对的时序侧信道
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    ring::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// 管理端鉴权状态
///
/// 取代旧实现里「`base64(user:password)` 直接当 cookie + 全局环境变量传递 +
/// `OnceLock` 首次读值永久缓存」的做法，修复两类缺陷：
///
/// 1. **会话凭证可逆**：旧 cookie 内容就是可逆的 base64 明文凭据，泄露即等于
///    密码泄露，且永不过期。现在 cookie 是 32 字节随机令牌，只存在于服务端
///    内存中，并带绝对过期时间。
/// 2. **默认回退与竞态**：旧实现把凭据写进进程环境变量再由登录线程首次读取，
///    读不到就回退 `admin/admin` 并永久缓存。现在凭据以 `Arc` 直接注入路由，
///    没有环境变量、没有缓存、也没有默认值——未配置即拒绝登录。
pub(crate) struct WebAuth {
    user: Option<String>,
    password: Option<String>,
    /// token -> 过期时间
    sessions: RwLock<std::collections::HashMap<String, Instant>>,
    /// 登录爆破防护（P1-3）：连续失败计数 + 锁定截止时间
    throttle: RwLock<LoginThrottle>,
}

/// 登录失败节流状态。
///
/// 采用服务端全局计数（而非按 IP）：管理面板只有一组凭据，
/// 全局粒度实现简单且不会被伪造 X-Forwarded-For 绕过。
#[derive(Default)]
struct LoginThrottle {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

/// 连续失败达到该次数后锁定登录
pub(crate) const LOGIN_LOCK_THRESHOLD: u32 = 5;
/// 锁定时长
pub(crate) const LOGIN_LOCK_DURATION: Duration = Duration::from_secs(5 * 60);

impl LoginThrottle {
    /// 当前是否处于锁定状态
    fn is_locked(&mut self, now: Instant) -> bool {
        match self.locked_until {
            Some(until) if until > now => true,
            Some(_) => {
                // 锁定已过期，重置计数重新起算
                self.locked_until = None;
                self.consecutive_failures = 0;
                false
            }
            None => false,
        }
    }

    /// 记录一次失败，返回是否触发锁定
    fn record_failure(&mut self, now: Instant) -> bool {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= LOGIN_LOCK_THRESHOLD {
            self.locked_until = Some(now + LOGIN_LOCK_DURATION);
            true
        } else {
            false
        }
    }

    /// 登录成功后清零
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.locked_until = None;
    }
}

impl WebAuth {
    pub(crate) fn new(user: Option<String>, password: Option<String>) -> Self {
        Self {
            user,
            password,
            sessions: RwLock::new(std::collections::HashMap::new()),
            throttle: RwLock::new(LoginThrottle::default()),
        }
    }

    /// 是否启用了登录鉴权（用户名与密码都配置了才算启用）
    pub(crate) fn requires_login(&self) -> bool {
        self.user.is_some() && self.password.is_some()
    }

    /// 校验用户名/密码（两端都做常量时间比较）
    pub(crate) fn verify_credentials(&self, user: &str, password: &str) -> bool {
        match (&self.user, &self.password) {
            (Some(expected_user), Some(expected_password)) => {
                let user_ok = constant_time_eq(user, expected_user);
                let password_ok = constant_time_eq(password, expected_password);
                user_ok && password_ok
            }
            _ => false,
        }
    }

    /// 创建新会话，返回随机令牌
    ///
    /// 随机源不可用时返回 `None`（fail-closed，绝不下发可预测的会话）。
    pub(crate) async fn create_session(&self) -> Option<String> {
        let token = new_session_token()?;
        let mut sessions = self.sessions.write().await;
        purge_expired_sessions(&mut sessions);
        sessions.insert(token.clone(), Instant::now() + WEB_SESSION_TTL);
        Some(token)
    }

    /// 校验会话令牌是否有效且未过期
    pub(crate) async fn validate_session(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut sessions = self.sessions.write().await;
        purge_expired_sessions(&mut sessions);
        sessions
            .get(token)
            .map(|expires| *expires > Instant::now())
            .unwrap_or(false)
    }

    /// 注销会话
    pub(crate) async fn revoke_session(&self, token: &str) {
        if !token.is_empty() {
            self.sessions.write().await.remove(token);
        }
    }

    /// 尝试登录（P1-3 防爆破）：
    ///
    /// - 处于锁定期 → `Err(true)`，不做凭据比较
    /// - 凭据正确   → `Ok(())`，失败计数清零
    /// - 凭据错误   → `Err(false)`，连续失败达到阈值后锁定 [`LOGIN_LOCK_DURATION`]
    pub(crate) async fn attempt_login(&self, user: &str, password: &str) -> Result<(), bool> {
        let mut throttle = self.throttle.write().await;
        let now = Instant::now();
        if throttle.is_locked(now) {
            return Err(true);
        }
        if self.verify_credentials(user, password) {
            throttle.record_success();
            Ok(())
        } else {
            let locked = throttle.record_failure(now);
            Err(locked)
        }
    }
}

/// 清理已过期会话，避免会话表随运行时间无界增长
pub(crate) fn purge_expired_sessions(sessions: &mut std::collections::HashMap<String, Instant>) {
    let now = Instant::now();
    sessions.retain(|_, expires| *expires > now);
}

/// 生成 32 字节随机会话令牌（base64 编码）
pub(crate) fn new_session_token() -> Option<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 32];
    SystemRandom::new().fill(&mut buf).ok()?;
    Some(base64::encode(buf))
}

/// 从请求头中提取会话令牌
pub(crate) fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        part.trim()
            .strip_prefix(WEB_SESSION_COOKIE)
            .and_then(|rest| rest.strip_prefix('='))
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    })
}

fn create_routes(
    server: std::sync::Arc<Server>,
    auth: std::sync::Arc<WebAuth>,
    expose_metrics: bool,
) -> axum::Router {
    // /metrics 仅在显式开启时注册（安全评审 P1-4）：默认 404，
    // 避免 run_id / 代理名 / 流量计数等内部信息对未认证调用方泄露。
    // 注意 /api/metrics 是 Dashboard 自身的指标视图，始终受登录保护。
    let metrics_routes = if expose_metrics {
        axum::Router::new().route("/metrics", axum::routing::get(prometheus_handler))
    } else {
        axum::Router::new()
    };

    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/healthz", axum::routing::get(health_handler))
        .merge(metrics_routes)
        .route("/api/metrics", axum::routing::get(metrics_handler))
        .route("/api/controllers", axum::routing::get(controllers_handler))
        // 管理端 API（v1，对齐原版 frps server/api_router.go）
        .route("/api/serverinfo", axum::routing::get(serverinfo_handler))
        .route("/api/clients", axum::routing::get(clients_handler))
        .route(
            "/api/clients/:key",
            axum::routing::get(client_detail_handler),
        )
        .route(
            "/api/proxy/:type",
            axum::routing::get(proxy_by_type_handler),
        )
        .route(
            "/api/proxy/:type/:name",
            axum::routing::get(proxy_by_type_and_name_handler),
        )
        .route(
            "/api/proxies",
            axum::routing::get(proxies_handler).delete(delete_proxies_handler),
        )
        .route(
            "/api/proxies/:name",
            axum::routing::get(proxy_by_name_handler),
        )
        .route(
            "/api/traffic/:name",
            axum::routing::get(proxy_traffic_handler),
        )
        // 管理端 API（v2，统一 {code,msg,data} 信封）
        .route("/api/v2/users", axum::routing::get(v2_users_handler))
        .route(
            "/api/v2/system/info",
            axum::routing::get(v2_system_info_handler),
        )
        .route(
            "/api/v2/system/prune",
            axum::routing::post(v2_system_prune_handler),
        )
        .route("/api/v2/clients", axum::routing::get(v2_clients_handler))
        .route(
            "/api/v2/clients/:key",
            axum::routing::get(v2_client_detail_handler),
        )
        .route("/api/v2/proxies", axum::routing::get(v2_proxies_handler))
        .route(
            "/api/v2/proxies/:name",
            axum::routing::get(v2_proxy_detail_handler),
        )
        .route(
            "/api/v2/proxies/:name/traffic",
            axum::routing::get(v2_proxy_traffic_handler),
        )
        .route("/", axum::routing::get(index_handler))
        .route("/index.html", axum::routing::get(index_handler))
        .route("/login", axum::routing::get(login_handler))
        .route("/login", axum::routing::post(login_post_handler))
        .route("/logout", axum::routing::get(logout_handler))
        .route("/api/reload", axum::routing::post(reload_handler))
        .with_state(server)
        .layer(axum::Extension(auth.clone()));

    if auth.requires_login() {
        log::info!("Web server authentication enabled");
        app.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let auth = auth.clone();
                async move {
                    let path = request.uri().path();

                    // 登录页、存活探针与指标端点免鉴权：
                    // /health 必须放行，否则容器探针会一直被 303 打回。
                    // /metrics 仅在 expose_metrics 开启时存在且免鉴权（P1-4）。
                    if path == "/login"
                        || path == "/health"
                        || path == "/healthz"
                        || (expose_metrics && path == "/metrics")
                    {
                        return next.run(request).await;
                    }

                    let session_valid = match session_token_from_headers(request.headers()) {
                        Some(token) => auth.validate_session(&token).await,
                        None => false,
                    };

                    if session_valid {
                        next.run(request).await
                    } else {
                        axum::response::Redirect::to("/login").into_response()
                    }
                }
            },
        ))
    } else {
        log::warn!(
            "Web server authentication is DISABLED: no web_server.user/password configured, \
             the dashboard is reachable by anyone who can reach the port"
        );
        app
    }
}

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "timestamp": get_timestamp(),
    }))
}

async fn reload_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    if let Some(ref tx) = server.reload_tx {
        match tx.send(()).await {
            Ok(_) => (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "success": true,
                    "message": "Reload signal sent"
                })),
            ),
            Err(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to send reload signal"
                })),
            ),
        }
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Hot reload not configured (config_path not set)"
            })),
        )
    }
}

async fn metrics_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<serde_json::Value> {
    let metrics = server.metrics.get_metrics();
    axum::Json(metrics)
}

/// Prometheus text exposition format 端点（免认证，供 Prometheus 抓取）
async fn prometheus_handler() -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        global_metrics().render_prometheus(),
    )
}

async fn controllers_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let clients = server.control_manager.get_clients().await;
    let controller_list: Vec<serde_json::Value> = clients
        .into_iter()
        .map(|client| {
            serde_json::json!({
                "user": client.user,
                "client_id": client.client_id,
                "run_id": client.run_id,
                "connected_at": client.connected_at.elapsed().as_secs(),
                "last_heartbeat": client.last_heartbeat.elapsed().as_secs(),
            })
        })
        .collect();
    axum::Json(controller_list)
}

async fn proxies_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let proxies = server.proxy_manager.proxies.read().await;
    let owners = server.proxy_manager.proxy_owners.read().await;
    let clients = server.control_manager.get_clients().await;
    let client_map: std::collections::HashMap<String, String> = clients
        .into_iter()
        .map(|c| (c.run_id, c.client_id))
        .collect();

    let proxy_list: Vec<serde_json::Value> = proxies
        .values()
        .map(|proxy| {
            let client_id = owners
                .get(&proxy.name)
                .and_then(|run_id| client_map.get(run_id))
                .cloned()
                .unwrap_or_else(|| "-".to_string());

            // 累计流量（服务端视角）：in = 访问者→工作连接，out = 工作连接→访问者
            let (traffic_in, traffic_out) = crate::metrics::global_metrics()
                .get_proxy_stat(&proxy.name)
                .map(|st| {
                    (
                        st.bytes_in.load(std::sync::atomic::Ordering::SeqCst),
                        st.bytes_out.load(std::sync::atomic::Ordering::SeqCst),
                    )
                })
                .unwrap_or((0, 0));

            serde_json::json!({
                "name": proxy.name,
                "type": proxy.r#type,
                "local_ip": proxy.local_ip,
                "local_port": proxy.local_port,
                "remote_port": proxy.remote_port,
                "plugin": proxy.plugin,
                "client": client_id,
                "traffic_in": traffic_in,
                "traffic_out": traffic_out,
            })
        })
        .collect();
    axum::Json(proxy_list)
}

async fn index_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web_ui.html"))
}

async fn login_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../login.html"))
}

pub(crate) async fn login_post_handler(
    axum::extract::Extension(auth): axum::extract::Extension<std::sync::Arc<WebAuth>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> axum::response::Response {
    let parts: Vec<(String, String)> = body
        .split('&')
        .filter_map(|s| {
            let mut parts = s.split('=');
            let key = parts.next()?.replace('+', " ");
            let value = parts.next()?.replace('+', " ");
            Some((
                key,
                urlencoding::decode(&value).unwrap_or_default().to_string(),
            ))
        })
        .collect();

    let username: String = parts
        .iter()
        .find(|(k, _)| k == "username")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let password: String = parts
        .iter()
        .find(|(k, _)| k == "password")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    // 未配置凭据时不允许登录（不再回退 admin/admin）；
    // 凭据校验接入防爆破节流（P1-3）：连续失败达阈值后锁定一段时间
    if !auth.requires_login() {
        tokio::time::sleep(Duration::from_millis(300)).await;
        return axum::http::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED)
            .header(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )
            .body(axum::body::Body::from("Unauthorized"))
            .unwrap_or_else(|_| axum::http::StatusCode::UNAUTHORIZED.into_response());
    }

    if let Err(locked) = auth.attempt_login(&username, &password).await {
        // 固定小延时，抬高在线暴力破解成本；锁定期内同样延时但不提示差异
        tokio::time::sleep(Duration::from_millis(300)).await;
        log::warn!(
            "Web login failed (locked={}) for user: {}",
            locked,
            username
        );
        return axum::http::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED)
            .header(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )
            .body(axum::body::Body::from("Unauthorized"))
            .unwrap_or_else(|_| axum::http::StatusCode::UNAUTHORIZED.into_response());
    }

    let token = match auth.create_session().await {
        Some(token) => token,
        None => {
            log::error!("Failed to generate session token: secure RNG unavailable");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 仅在反向代理声明 HTTPS 时才加 Secure，避免明文部署下 cookie 无法回传
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);

    let cookie = format!(
        "{cookie}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}",
        cookie = WEB_SESSION_COOKIE,
        token = token,
        max_age = WEB_SESSION_TTL.as_secs(),
        secure = if secure { "; Secure" } else { "" },
    );

    let mut response = axum::response::Redirect::to("/").into_response();
    match axum::http::HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response
                .headers_mut()
                .insert(axum::http::header::SET_COOKIE, value);
        }
        Err(_) => {
            log::error!("Failed to build session cookie header");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    response
}

pub(crate) async fn logout_handler(
    axum::extract::Extension(auth): axum::extract::Extension<std::sync::Arc<WebAuth>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Some(token) = session_token_from_headers(&headers) {
        auth.revoke_session(&token).await;
    }

    let mut response = axum::response::Redirect::to("/login").into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "frp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    response
}

/// Web 服务器（基于 axum）
pub struct WebServer {
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
    user: Option<String>,
    password: Option<String>,
    expose_metrics: bool,
}

impl WebServer {
    pub fn new(
        config: &rust_frp_config::WebServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self {
            addr,
            server: None,
            user: config.user.clone(),
            password: config.password.clone(),
            expose_metrics: config.expose_metrics,
        })
    }

    pub async fn start(&mut self, server: &Server) -> Result<(), Box<dyn std::error::Error>> {
        let server = std::sync::Arc::new(server.clone());
        let auth = std::sync::Arc::new(WebAuth::new(self.user.clone(), self.password.clone()));

        let app = create_routes(server, auth, self.expose_metrics);
        self.start_http(app).await?;
        Ok(())
    }

    async fn start_http(&mut self, app: axum::Router) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        log::info!("Web server listening on http://{}", self.addr);

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("Web server terminated with error: {}", e);
            }
        });

        self.server = Some(handle);
        Ok(())
    }
}
