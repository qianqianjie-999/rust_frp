//! tcpmux：HTTP CONNECT 单端口复用
//!
//! 服务器在 `tcpmux_http_connect_port` 上集中监听，解析客户端发来的 HTTP
//! CONNECT 请求，按请求行 authority（回退 `Host` 头）取域名，配合可选的
//! `Proxy-Authorization` 用户完成路由匹配，再向该 tcpmux 代理的持有客户端
//! 申请一条工作连接并与 CONNECT 连接双向桥接。
//!
//! 与 HTTP 虚拟主机（[`crate::vhost`]）的区别：tcpmux 的访问者连接不是
//! HTTP 请求，而是「先 CONNECT 建隧道、随后跑任意 TCP 协议」，因此不走
//! HTTP 响应改写路径，仅做 200/4xx 应答后原样桥接。

use base64::Engine as _;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::*;

/// 请求头长度上限（防止超长头部耗尽内存）
const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// 申请工作连接的超时
const WORK_CONN_TIMEOUT: Duration = Duration::from_secs(30);

/// CONNECT 建立成功应答
const RESP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// 请求格式错误
const RESP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 域名无匹配代理
const RESP_NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 代理要求认证但凭据缺失/不符
const RESP_UNAUTHORIZED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"tcpmux\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// 后端不可用（无持有者 / 工作连接失败）
const RESP_BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// 一条 tcpmux 路由：某个代理在一个域名上的注册项
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpMuxRoute {
    /// 代理名称
    pub proxy_name: String,
    /// 要求的 HTTP 基本认证用户名（空 = 不校验）
    pub http_user: Option<String>,
    /// 要求的 HTTP 基本认证密码（空 = 不校验）
    pub http_password: Option<String>,
    /// 按 HTTP 用户路由：设置后仅该用户可匹配本路由
    pub route_by_http_user: Option<String>,
}

/// 路由解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    /// 没有匹配的域名（404）
    NotFound,
    /// 命中域名但凭据不符（407）
    Unauthorized,
    /// 命中路由
    Matched(TcpMuxRoute),
}

/// tcpmux 路由表
///
/// 一个域名可挂多条路由（`route_by_http_user` 用于区分），因此内部按
/// `domain -> Vec<route>` 组织，与 HTTP 虚拟主机的「一域一代理」不同。
#[derive(Default)]
pub struct TcpMuxRouter {
    /// domain -> 该域名下的路由列表
    routes: RwLock<HashMap<String, Vec<TcpMuxRoute>>>,
    /// proxy_name -> 已注册域名（注销时按代理名回收）
    proxy_domains: RwLock<HashMap<String, Vec<String>>>,
}

impl TcpMuxRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册（或覆盖）一个代理的多个域名
    pub async fn register(&self, domains: Vec<String>, route: TcpMuxRoute) {
        let proxy_name = route.proxy_name.clone();
        {
            let mut routes = self.routes.write().await;
            for domain in &domains {
                let list = routes.entry(domain.clone()).or_default();
                // 同名代理重复注册时按代理名去重（热重载可能重复注册）
                list.retain(|r| r.proxy_name != proxy_name);
                list.push(route.clone());
            }
        }
        self.proxy_domains.write().await.insert(proxy_name, domains);
    }

    /// 注销一个代理的全部域名
    pub async fn unregister(&self, proxy_name: &str) {
        let Some(domains) = self.proxy_domains.write().await.remove(proxy_name) else {
            return;
        };
        let mut routes = self.routes.write().await;
        for domain in domains {
            if let Some(list) = routes.get_mut(&domain) {
                list.retain(|r| r.proxy_name != proxy_name);
                if list.is_empty() {
                    routes.remove(&domain);
                }
            }
        }
    }

    /// 解析路由：精确域名优先，其次后缀匹配（与 HTTP vhost 语义一致）
    ///
    /// - 命中且凭据相符 → [`RouteOutcome::Matched`]
    /// - 命中域名但所有候选都要求认证且凭据不符 → [`RouteOutcome::Unauthorized`]
    /// - 无候选 → [`RouteOutcome::NotFound`]
    pub async fn resolve(
        &self,
        domain: &str,
        user: Option<&str>,
        password: Option<&str>,
    ) -> RouteOutcome {
        let routes = self.routes.read().await;

        let mut candidates: Vec<TcpMuxRoute> = Vec::new();
        if let Some(list) = routes.get(domain) {
            candidates.extend(list.iter().cloned());
        }
        if candidates.is_empty() {
            for (registered, list) in routes.iter() {
                if domain.ends_with(registered.as_str()) {
                    candidates.extend(list.iter().cloned());
                }
            }
        }
        if candidates.is_empty() {
            return RouteOutcome::NotFound;
        }

        // route_by_http_user：配置了该字段的路由只接受对应用户
        candidates.retain(|r| match &r.route_by_http_user {
            Some(expected) => user == Some(expected.as_str()),
            None => true,
        });
        if candidates.is_empty() {
            return RouteOutcome::NotFound;
        }

        let mut saw_auth_requirement = false;
        for route in &candidates {
            if credential_match(route, user, password) {
                return RouteOutcome::Matched(route.clone());
            }
            saw_auth_requirement = true;
        }
        if saw_auth_requirement {
            RouteOutcome::Unauthorized
        } else {
            RouteOutcome::NotFound
        }
    }
}

/// 凭据匹配：路由未配置任何凭据时直接放行，否则常量时间比较
fn credential_match(route: &TcpMuxRoute, user: Option<&str>, password: Option<&str>) -> bool {
    let expect_user = route.http_user.as_deref().unwrap_or("");
    let expect_password = route.http_password.as_deref().unwrap_or("");
    if expect_user.is_empty() && expect_password.is_empty() {
        return true;
    }
    rust_frp_auth::constant_time_compare(user.unwrap_or("").as_bytes(), expect_user.as_bytes())
        && rust_frp_auth::constant_time_compare(
            password.unwrap_or("").as_bytes(),
            expect_password.as_bytes(),
        )
}

/// 解析后的 CONNECT 请求
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// 目标域名（已去端口）
    pub host: String,
    /// `Proxy-Authorization` 中的用户名
    pub user: Option<String>,
    /// `Proxy-Authorization` 中的密码
    pub password: Option<String>,
}

/// 解析 HTTP CONNECT 请求头
///
/// 仅接受 `CONNECT` 方法；域名优先取请求行中的 authority（RFC 7231 对
/// CONNECT 的定义），缺失时回退 `Host` 头。方法不符 / 无域名 / 头部不是
/// 合法 UTF-8 时返回 `None`。
pub fn parse_connect_request(head: &[u8]) -> Option<ConnectRequest> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    // 请求行必须为「方法 目标 HTTP/x.y」三段，避免把畸形请求当成合法 CONNECT
    let version = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") || !version.starts_with("HTTP/") {
        return None;
    }

    let mut header_host = String::new();
    let mut user = None;
    let mut password = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "host" => header_host = strip_port(value),
            "proxy-authorization" => {
                if let Some((u, p)) = parse_basic_credentials(value) {
                    user = Some(u);
                    password = Some(p);
                }
            }
            _ => {}
        }
    }

    let host = if target.is_empty() {
        header_host
    } else {
        strip_port(target)
    };
    if host.is_empty() {
        return None;
    }

    Some(ConnectRequest {
        host,
        user,
        password,
    })
}

/// 去掉 `host:port` 中的端口部分
fn strip_port(value: &str) -> String {
    value.split(':').next().unwrap_or(value).trim().to_string()
}

/// 解析 `Basic base64(user:password)`
fn parse_basic_credentials(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// 读取到首个空行（含）为止，返回 `(头, 剩余载荷)`
///
/// 超过 [`MAX_REQUEST_HEAD`] 或连接先关闭返回 `Ok(None)`。
async fn read_request_head(conn: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let leftover = buf.split_off(end);
            return Ok(Some((buf, leftover)));
        }
        if buf.len() >= MAX_REQUEST_HEAD {
            return Ok(None);
        }
        let n = conn.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// 定位 `\r\n\r\n` 结束位置（返回其后的下标）
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// 复用器运行期依赖（全部为 Arc 克隆，代价 O(1)）
pub struct TcpMuxDeps {
    pub router: Arc<TcpMuxRouter>,
    pub proxy_owners: Arc<RwLock<HashMap<String, String>>>,
    pub control_manager: Arc<ControlManager>,
    pub work_conn_manager: Arc<ServerWorkConnManager>,
    pub plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

/// tcpmux 监听循环：`shutdown` 通知后退出（监听器随作用域结束关闭）
pub async fn run_tcpmux_listener(
    listener: TcpListener,
    deps: TcpMuxDeps,
    shutdown: Arc<tokio::sync::Notify>,
) {
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = shutdown.notified() => {
                log::info!("Shutdown signal received, tcpmux accept loop stopped");
                return;
            }
        };

        match accepted {
            Ok((conn, peer)) => {
                let deps = TcpMuxDeps {
                    router: deps.router.clone(),
                    proxy_owners: deps.proxy_owners.clone(),
                    control_manager: deps.control_manager.clone(),
                    work_conn_manager: deps.work_conn_manager.clone(),
                    plugin_manager: deps.plugin_manager.clone(),
                };
                tokio::spawn(serve_conn(conn, peer, deps));
            }
            Err(e) => {
                log::error!("tcpmux accept error: {:?}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// 处理单个 CONNECT 连接：解析 → 路由 → 申请工作连接 → 应答并桥接
async fn serve_conn(mut conn: TcpStream, peer: SocketAddr, deps: TcpMuxDeps) {
    let (head, leftover) = match read_request_head(&mut conn).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            let _ = conn.write_all(RESP_BAD_REQUEST).await;
            return;
        }
        Err(e) => {
            log::debug!("tcpmux: read request from {} failed: {}", peer, e);
            return;
        }
    };

    let Some(req) = parse_connect_request(&head) else {
        log::debug!("tcpmux: malformed CONNECT request from {}", peer);
        let _ = conn.write_all(RESP_BAD_REQUEST).await;
        return;
    };

    let route = match deps
        .router
        .resolve(&req.host, req.user.as_deref(), req.password.as_deref())
        .await
    {
        RouteOutcome::Matched(route) => route,
        RouteOutcome::Unauthorized => {
            log::warn!(
                "tcpmux: authentication failed for host [{}] from {}",
                req.host,
                peer
            );
            let _ = conn.write_all(RESP_UNAUTHORIZED).await;
            return;
        }
        RouteOutcome::NotFound => {
            log::debug!("tcpmux: no route for host [{}] from {}", req.host, peer);
            let _ = conn.write_all(RESP_NOT_FOUND).await;
            return;
        }
    };

    // 已匹配到代理：统计连接数（drop 时自动减一）
    let _conn_guard = global_metrics()
        .get_proxy_stat(&route.proxy_name)
        .map(ProxyConnGuard::acquire);

    // 服务端插件回调：NewUserConn（可拒绝本次外部接入）
    if let Err(reason) = crate::proxy_manager::notify_new_user_conn(
        &deps.plugin_manager,
        &deps.control_manager,
        &deps.proxy_owners,
        route.proxy_name.as_str(),
        "tcpmux",
        &peer.to_string(),
    )
    .await
    {
        log::warn!(
            "tcpmux: user conn from {} for proxy [{}] rejected by http plugin: {}",
            peer,
            route.proxy_name,
            reason
        );
        let _ = conn.write_all(RESP_BAD_GATEWAY).await;
        return;
    }

    let run_id = {
        let owners = deps.proxy_owners.read().await;
        owners.get(&route.proxy_name).cloned()
    };
    let Some(run_id) = run_id else {
        log::error!("tcpmux: no owner for proxy [{}]", route.proxy_name);
        let _ = conn.write_all(RESP_BAD_GATEWAY).await;
        return;
    };
    let Some(msg_tx) = deps.control_manager.get_msg_tx(&run_id).await else {
        log::error!("tcpmux: no control channel for run_id [{}]", run_id);
        let _ = conn.write_all(RESP_BAD_GATEWAY).await;
        return;
    };

    let mut work_conn = match deps
        .work_conn_manager
        .get_work_conn(&route.proxy_name, &msg_tx, WORK_CONN_TIMEOUT, peer)
        .await
    {
        Ok(conn) => conn,
        Err(e) => {
            log::error!(
                "tcpmux: failed to get work conn for [{}]: {}",
                route.proxy_name,
                e
            );
            let _ = conn.write_all(RESP_BAD_GATEWAY).await;
            return;
        }
    };

    // 通知访问者隧道已建立；随后进入透明转发
    if let Err(e) = conn.write_all(RESP_OK).await {
        log::debug!("tcpmux: write 200 response to {} failed: {}", peer, e);
        return;
    }
    // 部分客户端不等应答即发送载荷，头部之后的字节需先补给工作连接
    if !leftover.is_empty() {
        if let Err(e) = work_conn.write_all(&leftover).await {
            log::error!(
                "tcpmux: forward pipelined payload for [{}] failed: {}",
                route.proxy_name,
                e
            );
            return;
        }
    }

    match rust_frp_util::bridge_streams_counted(conn, work_conn).await {
        Ok((to_work, to_visitor)) => {
            global_metrics().record_traffic(&route.proxy_name, to_work, to_visitor);
        }
        Err(e) => log::error!(
            "tcpmux: bridge error for proxy [{}]: {:?}",
            route.proxy_name,
            e
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(proxy_name: &str) -> TcpMuxRoute {
        TcpMuxRoute {
            proxy_name: proxy_name.to_string(),
            http_user: None,
            http_password: None,
            route_by_http_user: None,
        }
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, password))
        )
    }

    #[test]
    fn test_parse_connect_request_authority_and_auth() {
        let head = format!(
            "CONNECT web.example.com:443 HTTP/1.1\r\nHost: web.example.com:443\r\nProxy-Authorization: {}\r\n\r\n",
            basic("alice", "s3cret")
        );
        let req = parse_connect_request(head.as_bytes()).expect("valid CONNECT");
        assert_eq!(req.host, "web.example.com");
        assert_eq!(req.user.as_deref(), Some("alice"));
        assert_eq!(req.password.as_deref(), Some("s3cret"));
    }

    #[test]
    fn test_parse_connect_request_rejects_non_connect_and_missing_host() {
        assert!(parse_connect_request(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n").is_none());
        // 请求行缺少目标/版本段 → 拒绝
        assert!(parse_connect_request(b"CONNECT\r\n\r\n").is_none());
        assert!(parse_connect_request(b"CONNECT example.com:80\r\n\r\n").is_none());
        // 目标与版本段错位（双空格）也可被版本校验拦下
        assert!(parse_connect_request(b"CONNECT  HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn test_parse_connect_request_tolerates_bad_auth_header() {
        let head = b"CONNECT a.com:80 HTTP/1.1\r\nProxy-Authorization: Bearer xyz\r\n\r\n";
        let req = parse_connect_request(head).expect("valid CONNECT");
        assert_eq!(req.host, "a.com");
        assert_eq!(req.user, None);
        assert_eq!(req.password, None);
    }

    #[test]
    fn test_find_head_end() {
        assert_eq!(find_head_end(b"a\r\n\r\n"), Some(5));
        assert_eq!(find_head_end(b"a\r\nb\r\n\r\nrest"), Some(8));
        assert_eq!(find_head_end(b"no terminator"), None);
    }

    #[tokio::test]
    async fn test_router_exact_and_suffix_match() {
        let router = TcpMuxRouter::new();
        router
            .register(vec!["web.example.com".to_string()], route("p1"))
            .await;

        assert_eq!(
            router.resolve("web.example.com", None, None).await,
            RouteOutcome::Matched(route("p1"))
        );
        // 后缀匹配（子域名）
        assert_eq!(
            router.resolve("a.web.example.com", None, None).await,
            RouteOutcome::Matched(route("p1"))
        );
        assert_eq!(
            router.resolve("other.com", None, None).await,
            RouteOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn test_router_auth_required_and_unregister() {
        let router = TcpMuxRouter::new();
        let mut secured = route("p1");
        secured.http_user = Some("alice".to_string());
        secured.http_password = Some("pw".to_string());
        router
            .register(vec!["web.example.com".to_string()], secured)
            .await;

        assert_eq!(
            router.resolve("web.example.com", None, None).await,
            RouteOutcome::Unauthorized
        );
        assert_eq!(
            router
                .resolve("web.example.com", Some("alice"), Some("bad"))
                .await,
            RouteOutcome::Unauthorized
        );
        assert!(matches!(
            router
                .resolve("web.example.com", Some("alice"), Some("pw"))
                .await,
            RouteOutcome::Matched(_)
        ));

        router.unregister("p1").await;
        assert_eq!(
            router
                .resolve("web.example.com", Some("alice"), Some("pw"))
                .await,
            RouteOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn test_router_route_by_http_user() {
        let router = TcpMuxRouter::new();
        let mut alice = route("p-alice");
        alice.route_by_http_user = Some("alice".to_string());
        alice.http_user = Some("alice".to_string());
        alice.http_password = Some("pw".to_string());
        let mut bob = route("p-bob");
        bob.route_by_http_user = Some("bob".to_string());
        bob.http_user = Some("bob".to_string());
        bob.http_password = Some("pw".to_string());
        router
            .register(vec!["shared.example.com".to_string()], alice)
            .await;
        router
            .register(vec!["shared.example.com".to_string()], bob)
            .await;

        match router
            .resolve("shared.example.com", Some("bob"), Some("pw"))
            .await
        {
            RouteOutcome::Matched(r) => assert_eq!(r.proxy_name, "p-bob"),
            other => panic!("unexpected: {:?}", other),
        }
        // 用户 carol 不属于任何路由 → 视为无匹配
        assert_eq!(
            router
                .resolve("shared.example.com", Some("carol"), Some("pw"))
                .await,
            RouteOutcome::NotFound
        );
    }

    #[tokio::test]
    async fn test_router_re_register_replaces_same_proxy() {
        let router = TcpMuxRouter::new();
        router
            .register(vec!["a.com".to_string()], route("p1"))
            .await;
        router
            .register(vec!["a.com".to_string()], route("p1"))
            .await;
        // 重复注册不应产生重复候选
        match router.resolve("a.com", None, None).await {
            RouteOutcome::Matched(r) => assert_eq!(r.proxy_name, "p1"),
            other => panic!("unexpected: {:?}", other),
        }
        router.unregister("p1").await;
        assert_eq!(
            router.resolve("a.com", None, None).await,
            RouteOutcome::NotFound
        );
    }

    /// 启动一个仅用于应答路径测试的复用器，返回监听地址
    async fn start_muxer(router: Arc<TcpMuxRouter>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let deps = TcpMuxDeps {
            router,
            proxy_owners: Arc::new(RwLock::new(HashMap::new())),
            control_manager: Arc::new(ControlManager::new()),
            work_conn_manager: Arc::new(ServerWorkConnManager::new(1)),
            plugin_manager: Arc::new(rust_frp_plugin::server_plugin::Manager::default()),
        };
        tokio::spawn(run_tcpmux_listener(
            listener,
            deps,
            Arc::new(tokio::sync::Notify::new()),
        ));
        addr
    }

    /// 发送一段原始请求并读回应答首行
    async fn send_head(addr: SocketAddr, head: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(head.as_bytes()).await.expect("write head");
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[tokio::test]
    async fn test_muxer_response_paths() {
        let router = Arc::new(TcpMuxRouter::new());
        let mut secured = route("secured");
        secured.http_user = Some("alice".to_string());
        secured.http_password = Some("pw".to_string());
        router
            .register(vec!["secured.example.com".to_string()], secured)
            .await;
        router
            .register(vec!["open.example.com".to_string()], route("open"))
            .await;
        let addr = start_muxer(router).await;

        // 域名无路由 → 404
        let resp = send_head(
            addr,
            "CONNECT unknown.example.com:443 HTTP/1.1\r\nHost: unknown.example.com:443\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 404"), "got {resp:?}");

        // 命中但缺少凭据 → 407
        let resp = send_head(
            addr,
            "CONNECT secured.example.com:443 HTTP/1.1\r\nHost: secured.example.com:443\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got {resp:?}");

        // 非 CONNECT 方法 → 400
        let resp = send_head(addr, "GET / HTTP/1.1\r\nHost: open.example.com\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 400"), "got {resp:?}");

        // 命中且无需认证，但当前无代理持有者 → 502
        let resp = send_head(
            addr,
            "CONNECT open.example.com:443 HTTP/1.1\r\nHost: open.example.com:443\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 502"), "got {resp:?}");
    }
}
