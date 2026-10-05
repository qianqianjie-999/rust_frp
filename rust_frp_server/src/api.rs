//! frps 管理端 API：对齐原版 frp 的 `/api/*`（v1）与 `/api/v2/*` 套件
//!
//! # 覆盖范围（与原版 `server/api_router.go` 对照）
//!
//! v1：
//! - `GET /api/serverinfo`
//! - `GET /api/proxy/{type}`、`GET /api/proxy/{type}/{name}`
//! - `GET /api/proxies/{name}`、`DELETE /api/proxies?status=offline`
//! - `GET /api/traffic/{name}`
//! - `GET /api/clients`、`GET /api/clients/{key}`
//!
//! v2（统一 `{code, msg, data}` 信封）：
//! - `GET /api/v2/system/info`、`POST /api/v2/system/prune`
//! - `GET /api/v2/users`
//! - `GET /api/v2/clients`、`GET /api/v2/clients/{key}`
//! - `GET /api/v2/proxies`、`GET /api/v2/proxies/{name}`、
//!   `GET /api/v2/proxies/{name}/traffic`
//!
//! # 语义差异（有意为之）
//!
//! - `/api/clients` 的 `key` 为 `base64url(user|clientID|runID)`，可直接放进路径，
//!   无需原版的额外 URL 编码层。
//! - 离线代理历史保存在进程内存（上限 [`crate::metrics::MAX_CLOSED_PROXIES`]），
//!   重启即清空；原版由内存 StatsCollector 提供，行为一致。

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::control::ClientInfo;
use crate::metrics::ClosedProxyInfo;
use crate::Server;

/// v2 分页默认值（对齐原版）
const DEFAULT_V2_PAGE: usize = 1;
const DEFAULT_V2_PAGE_SIZE: usize = 50;
const MAX_V2_PAGE_SIZE: usize = 200;

/// 支持的代理类型（用于 `/api/proxy/{type}` 与 v2 的 `type` 过滤校验）
const PROXY_TYPES: &[&str] = &[
    "tcp",
    "udp",
    "http",
    "https",
    "tcpmux",
    "stcp",
    "xtcp",
    "sudp",
    "websocket",
];

// ---------------------------------------------------------------------------
// 通用响应工具
// ---------------------------------------------------------------------------

/// v1 风格错误响应：HTTP 状态码 + `{code, msg}`
fn v1_error(status: axum::http::StatusCode, msg: &str) -> axum::response::Response {
    (
        status,
        axum::Json(json!({ "code": status.as_u16(), "msg": msg })),
    )
        .into_response()
}

/// v2 风格错误响应：统一 200 之外的 HTTP 状态码 + `{code, msg, data:null}`
fn v2_error(status: axum::http::StatusCode, msg: &str) -> axum::response::Response {
    (
        status,
        axum::Json(json!({ "code": status.as_u16(), "msg": msg, "data": Value::Null })),
    )
        .into_response()
}

/// v2 成功响应信封
fn v2_ok(data: Value) -> axum::Json<Value> {
    axum::Json(json!({ "code": 200, "msg": "success", "data": data }))
}

/// 解析 v2 分页参数，返回 `(page, page_size)` 或错误响应
///
/// `allow(result_large_err)`：错误分支直接携带已构造好的 HTTP 响应，
/// 装箱只是搬运一个大结构、不减少分配，收益为负。
#[allow(clippy::result_large_err)]
fn parse_v2_page(
    query: &HashMap<String, String>,
) -> Result<(usize, usize), axum::response::Response> {
    let parse = |raw: Option<&String>, default: usize, name: &str| -> Result<usize, String> {
        match raw {
            None => Ok(default),
            Some(v) if v.is_empty() => Ok(default),
            Some(v) => match v.parse::<usize>() {
                Ok(n) if n >= 1 => Ok(n),
                _ => Err(format!("{name} must be a positive integer")),
            },
        }
    };
    let page = parse(query.get("page"), DEFAULT_V2_PAGE, "page")
        .map_err(|e| v2_error(axum::http::StatusCode::BAD_REQUEST, &e))?;
    let page_size = parse(query.get("pageSize"), DEFAULT_V2_PAGE_SIZE, "pageSize")
        .map_err(|e| v2_error(axum::http::StatusCode::BAD_REQUEST, &e))?;
    if page_size > MAX_V2_PAGE_SIZE {
        return Err(v2_error(
            axum::http::StatusCode::BAD_REQUEST,
            &format!("pageSize must be between 1 and {MAX_V2_PAGE_SIZE}"),
        ));
    }
    Ok((page, page_size))
}

/// v2 状态过滤：all（默认）/ online / offline
#[allow(clippy::result_large_err)]
fn parse_v2_status(raw: Option<&String>) -> Result<String, axum::response::Response> {
    let status = raw.map(|s| s.to_lowercase()).unwrap_or_default();
    match status.as_str() {
        "" | "all" | "online" | "offline" => Ok(status),
        _ => Err(v2_error(
            axum::http::StatusCode::BAD_REQUEST,
            "status must be one of all, online, offline",
        )),
    }
}

/// 按 online 状态与过滤条件匹配
fn status_matches(online: bool, filter: &str) -> bool {
    match filter {
        "online" => online,
        "offline" => !online,
        _ => true,
    }
}

/// 分页切片
fn paginate<T: Clone>(items: &[T], page: usize, page_size: usize) -> Vec<T> {
    let start = (page - 1) * page_size;
    if start >= items.len() {
        return Vec::new();
    }
    let end = (start + page_size).min(items.len());
    items[start..end].to_vec()
}

// ---------------------------------------------------------------------------
// 数据建模
// ---------------------------------------------------------------------------

/// 服务器信息（v1 `/api/serverinfo` 与 v2 config 段共用）
async fn build_server_info(server: &Server) -> Value {
    let cfg = server.config();
    let metrics = server.metrics.get_metrics();
    let num = |key: &str| metrics.get(key).and_then(Value::as_i64).unwrap_or(0);

    let proxy_type_counts = proxy_type_counts(server).await;
    let allow_ports = render_allow_ports(cfg);

    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "bindPort": cfg.bind_port,
        "vhostHTTPPort": cfg.vhost_http_port.unwrap_or(0),
        "vhostHTTPSPort": cfg.vhost_https_port.unwrap_or(0),
        "tcpmuxHTTPConnectPort": cfg.tcpmux_http_connect_port.unwrap_or(0),
        "kcpBindPort": cfg.kcp_bind_port.unwrap_or(0),
        "quicBindPort": cfg.quic_bind_port.unwrap_or(0),
        // rust_frp 暂未实现 subdomain 路由，字段保留以对齐原版响应结构
        "subdomainHost": "",
        "maxPoolCount": cfg.transport.pool_count,
        "maxPortsPerClient": cfg.max_ports_per_user.unwrap_or(0),
        "heartbeatTimeout": 90,
        "allowPortsStr": allow_ports,
        "tlsForce": cfg.transport.tls_only,
        // 方向对齐原版：in = 访问者 → 工作连接；out = 工作连接 → 访问者
        "totalTrafficIn": num("bytes_received"),
        "totalTrafficOut": num("bytes_sent"),
        "curConns": num("current_connections"),
        "clientCounts": server.control_manager.get_clients().await.len(),
        "proxyTypeCount": proxy_type_counts,
    })
}

/// 按类型统计在线代理数
async fn proxy_type_counts(server: &Server) -> Value {
    let proxies = server.proxy_manager.proxies.read().await;
    let mut counts: HashMap<String, i64> = HashMap::new();
    for proxy in proxies.values() {
        *counts.entry(proxy.r#type.clone()).or_insert(0) += 1;
    }
    serde_json::to_value(counts).unwrap_or_else(|_| json!({}))
}

/// 渲染 allow_ports 白名单为原版风格的字符串（如 `1000-2000,3000`）
fn render_allow_ports(cfg: &rust_frp_config::ServerConfig) -> String {
    let mut parts = Vec::new();
    for range in &cfg.allow_ports {
        if let Some(single) = range.single {
            parts.push(single.to_string());
        } else if let (Some(start), Some(end)) = (range.start, range.end) {
            parts.push(format!("{start}-{end}"));
        } else if let Some(start) = range.start {
            parts.push(start.to_string());
        }
    }
    parts.join(",")
}

/// 客户端信息 → 原版 `ClientInfoResp` 结构
fn build_client_resp(info: &ClientInfo) -> Value {
    json!({
        "key": info.key(),
        "user": info.user,
        "clientID": info.client_id,
        "runID": info.run_id,
        "version": info.version,
        "wireProtocol": info.wire_protocol,
        "hostname": info.hostname,
        "clientIP": info.client_ip,
        "firstConnectedAt": info.first_connected_at,
        // 以「上线时刻 = 现在 - 已过去秒数」还原绝对 Unix 时间
        "lastConnectedAt": rust_frp_util::get_timestamp() - info.connected_at.elapsed().as_secs() as i64,
        "disconnectedAt": info.disconnected_at.unwrap_or(0),
        "online": info.online,
    })
}

/// 代理配置 → 原版 `conf` 字段结构（保留原版字段命名）
fn build_proxy_conf(proxy: &rust_frp_config::ProxyConfig) -> Value {
    let mut conf = json!({
        "name": proxy.name,
        "type": proxy.r#type,
        "localIP": proxy.local_ip,
        "localPort": proxy.local_port,
        "plugin": proxy.plugin.as_ref().map(|p| p.r#type.clone()).unwrap_or_default(),
        "useEncryption": proxy.use_encryption,
        "useCompression": proxy.use_compression,
        "transport": {
            "useEncryption": proxy.use_encryption,
            "useCompression": proxy.use_compression,
            "bandwidthLimit": proxy.bandwidth_limit.clone().unwrap_or_default(),
        },
    });
    let obj = conf.as_object_mut().expect("literal object");
    if let Some(port) = proxy.remote_port {
        obj.insert("remotePort".to_string(), json!(port));
    }
    if let Some(domains) = &proxy.custom_domains {
        obj.insert("customDomains".to_string(), json!(domains));
    }
    if let Some(subdomain) = &proxy.subdomain {
        obj.insert("subdomain".to_string(), json!(subdomain));
    }
    if let Some(locations) = &proxy.locations {
        obj.insert("locations".to_string(), json!(locations));
    }
    if let Some(rewrite) = &proxy.host_header_rewrite {
        obj.insert("hostHeaderRewrite".to_string(), json!(rewrite));
    }
    if let Some(multiplexer) = &proxy.multiplexer {
        obj.insert("multiplexer".to_string(), json!(multiplexer));
    }
    if let Some(route_by) = &proxy.route_by_http_user {
        obj.insert("routeByHTTPUser".to_string(), json!(route_by));
    }
    if let Some(group) = &proxy.group {
        obj.insert("loadBalancer".to_string(), json!({ "group": group }));
    }
    conf
}

/// 在线代理的统计视图（`ProxyStatsInfo`）
fn build_proxy_stats(proxy: &rust_frp_config::ProxyConfig, client_id: &str, user: &str) -> Value {
    let stat = crate::metrics::global_metrics().get_proxy_stat(&proxy.name);
    let (traffic_in, traffic_out, cur_conns, last_start) = match &stat {
        Some(st) => (
            st.bytes_in.load(std::sync::atomic::Ordering::SeqCst) as i64,
            st.bytes_out.load(std::sync::atomic::Ordering::SeqCst) as i64,
            st.current_conns.load(std::sync::atomic::Ordering::SeqCst) as i64,
            st.created_at,
        ),
        None => (0, 0, 0, rust_frp_util::get_timestamp()),
    };
    json!({
        "name": proxy.name,
        "conf": build_proxy_conf(proxy),
        "user": user,
        "clientID": client_id,
        "todayTrafficIn": traffic_in,
        "todayTrafficOut": traffic_out,
        "curConns": cur_conns,
        "lastStartTime": format_timestamp(last_start),
        "lastCloseTime": "",
        "status": "online",
    })
}

/// 离线代理（历史）统计视图
fn build_closed_proxy_stats(info: &ClosedProxyInfo) -> Value {
    json!({
        "name": info.name,
        "conf": json!({
            "name": info.name,
            "type": info.proxy_type,
            "remotePort": info.remote_port,
        }),
        "user": info.user,
        "clientID": info.client_id,
        "todayTrafficIn": info.traffic_in as i64,
        "todayTrafficOut": info.traffic_out as i64,
        "curConns": 0,
        "lastStartTime": format_timestamp(info.last_start_time),
        "lastCloseTime": format_timestamp(info.last_close_time),
        "status": "offline",
    })
}

/// Unix 秒 → `YYYY-MM-DD HH:MM:SS`（**本地时区**，与日志时间戳同一套实现）
///
/// `secs <= 0`（从未启动过 / 未记录）返回空串，由前端渲染成占位符。
///
/// 时区来自进程的 `TZ` / `/etc/localtime`，取不到时回退 UTC —— 具体换算见
/// [`rust_frp_util::localtime`]。此前这里是自带的一份 UTC 实现，导致管理端
/// 显示的时间比本地时间早 8 小时。
fn format_timestamp(secs: i64) -> String {
    if secs <= 0 {
        return String::new();
    }
    rust_frp_util::localtime::format_local_datetime(secs)
}

/// 在线代理 + 离线的代理列表（`(name, stats_json, client_id, user, online)`）
async fn collect_all_proxy_stats(server: &Server) -> Vec<Value> {
    let proxies = server.proxy_manager.proxies.read().await.clone();
    let owners = server.proxy_manager.proxy_owners.read().await.clone();
    let clients = server.control_manager.get_clients().await;
    let client_map: HashMap<String, (String, String)> = clients
        .into_iter()
        .map(|c| (c.run_id.clone(), (c.client_id.clone(), c.user.clone())))
        .collect();

    let mut items: Vec<Value> = proxies
        .values()
        .map(|proxy| {
            let (client_id, user) = owners
                .get(&proxy.name)
                .and_then(|run_id| client_map.get(run_id))
                .cloned()
                .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
            build_proxy_stats(proxy, &client_id, &user)
        })
        .collect();
    items.extend(
        crate::metrics::global_metrics()
            .list_closed_proxies()
            .iter()
            .map(build_closed_proxy_stats),
    );
    items.sort_by(|a, b| {
        let ta = a.get("status").and_then(Value::as_str).unwrap_or("");
        let tb = b.get("status").and_then(Value::as_str).unwrap_or("");
        ta.cmp(tb).then_with(|| {
            let na = a.get("name").and_then(Value::as_str).unwrap_or("");
            let nb = b.get("name").and_then(Value::as_str).unwrap_or("");
            na.cmp(nb)
        })
    });
    items
}

/// 流量序列快照（在线取实时序列；离线取静态累计，返回单元素数组）
fn traffic_series_of(name: &str) -> Option<(Vec<i64>, Vec<i64>)> {
    if let Some(stat) = crate::metrics::global_metrics().get_proxy_stat(name) {
        let (incoming, outgoing) = stat.traffic_series();
        return Some((
            incoming.into_iter().map(|v| v as i64).collect(),
            outgoing.into_iter().map(|v| v as i64).collect(),
        ));
    }
    crate::metrics::global_metrics()
        .list_closed_proxies()
        .iter()
        .find(|p| p.name == name)
        .map(|p| (vec![p.traffic_in as i64], vec![p.traffic_out as i64]))
}

// ---------------------------------------------------------------------------
// v1 handlers
// ---------------------------------------------------------------------------

/// `GET /api/serverinfo`
pub async fn serverinfo_handler(State(server): State<Arc<Server>>) -> axum::Json<Value> {
    axum::Json(build_server_info(&server).await)
}

/// `GET /api/clients?user=&clientId=&runId=&status=`
pub async fn clients_handler(
    State(server): State<Arc<Server>>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::Json<Vec<Value>> {
    let user = query.get("user").cloned().unwrap_or_default();
    let client_id = query.get("clientId").cloned().unwrap_or_default();
    let run_id = query.get("runId").cloned().unwrap_or_default();
    let status = query
        .get("status")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let mut items: Vec<Value> = server
        .control_manager
        .get_all_clients()
        .await
        .iter()
        .filter(|c| user.is_empty() || c.user == user)
        .filter(|c| client_id.is_empty() || c.client_id == client_id)
        .filter(|c| run_id.is_empty() || c.run_id == run_id)
        .filter(|c| status_matches(c.online, &status))
        .map(build_client_resp)
        .collect();
    items.sort_by_key(|v| {
        (
            v.get("user")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            v.get("clientID")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )
    });
    axum::Json(items)
}

/// `GET /api/clients/{key}`
pub async fn client_detail_handler(
    State(server): State<Arc<Server>>,
    Path(key): Path<String>,
) -> axum::response::Response {
    match server.control_manager.get_client_by_key(&key).await {
        Some(info) => axum::Json(build_client_resp(&info)).into_response(),
        None => v1_error(
            axum::http::StatusCode::NOT_FOUND,
            &format!("client {key} not found"),
        ),
    }
}

/// `GET /api/proxy/{type}`
pub async fn proxy_by_type_handler(
    State(server): State<Arc<Server>>,
    Path(proxy_type): Path<String>,
) -> axum::response::Response {
    let proxy_type = proxy_type.to_lowercase();
    if !PROXY_TYPES.contains(&proxy_type.as_str()) {
        return v1_error(
            axum::http::StatusCode::BAD_REQUEST,
            &format!("invalid proxy type: {proxy_type}"),
        );
    }
    let mut proxies: Vec<Value> = collect_all_proxy_stats(&server)
        .await
        .into_iter()
        .filter(|v| {
            v.get("conf")
                .and_then(|c| c.get("type"))
                .and_then(Value::as_str)
                == Some(proxy_type.as_str())
        })
        .collect();
    proxies.sort_by_key(|v| {
        v.get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    });
    axum::Json(json!({ "proxies": proxies })).into_response()
}

/// `GET /api/proxy/{type}/{name}`
pub async fn proxy_by_type_and_name_handler(
    State(server): State<Arc<Server>>,
    Path((proxy_type, name)): Path<(String, String)>,
) -> axum::response::Response {
    let proxy_type = proxy_type.to_lowercase();
    if !PROXY_TYPES.contains(&proxy_type.as_str()) {
        return v1_error(
            axum::http::StatusCode::BAD_REQUEST,
            &format!("invalid proxy type: {proxy_type}"),
        );
    }
    match collect_all_proxy_stats(&server)
        .await
        .into_iter()
        .find(|v| {
            v.get("name").and_then(Value::as_str) == Some(name.as_str())
                && v.get("conf")
                    .and_then(|c| c.get("type"))
                    .and_then(Value::as_str)
                    == Some(proxy_type.as_str())
        }) {
        Some(stats) => axum::Json(stats).into_response(),
        None => v1_error(axum::http::StatusCode::NOT_FOUND, "no proxy info found"),
    }
}

/// `GET /api/proxies/{name}`
pub async fn proxy_by_name_handler(
    State(server): State<Arc<Server>>,
    Path(name): Path<String>,
) -> axum::response::Response {
    match collect_all_proxy_stats(&server)
        .await
        .into_iter()
        .find(|v| v.get("name").and_then(Value::as_str) == Some(name.as_str()))
    {
        Some(stats) => axum::Json(stats).into_response(),
        None => v1_error(axum::http::StatusCode::NOT_FOUND, "no proxy info found"),
    }
}

/// `GET /api/traffic/{name}`
pub async fn proxy_traffic_handler(Path(name): Path<String>) -> axum::response::Response {
    match traffic_series_of(&name) {
        Some((traffic_in, traffic_out)) => {
            axum::Json(json!({ "name": name, "trafficIn": traffic_in, "trafficOut": traffic_out }))
                .into_response()
        }
        None => v1_error(axum::http::StatusCode::NOT_FOUND, "no proxy info found"),
    }
}

/// `DELETE /api/proxies?status=offline`
pub async fn delete_proxies_handler(
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    match query.get("status").map(String::as_str) {
        Some("offline") => {
            let (cleared, total) = crate::metrics::global_metrics().clear_closed_proxies();
            log::info!("cleared [{cleared}] offline proxies, total [{total}] proxies");
            axum::Json(json!({ "code": 200, "msg": "success" })).into_response()
        }
        _ => v1_error(
            axum::http::StatusCode::BAD_REQUEST,
            "status only support offline",
        ),
    }
}

// ---------------------------------------------------------------------------
// v2 handlers（统一 {code, msg, data} 信封）
// ---------------------------------------------------------------------------

/// `GET /api/v2/system/info`
pub async fn v2_system_info_handler(State(server): State<Arc<Server>>) -> axum::Json<Value> {
    let info = build_server_info(&server).await;
    let pick = |k: &str| info.get(k).cloned().unwrap_or(Value::Null);
    v2_ok(json!({
        "version": pick("version"),
        "config": {
            "bindPort": pick("bindPort"),
            "vhostHTTPPort": pick("vhostHTTPPort"),
            "vhostHTTPSPort": pick("vhostHTTPSPort"),
            "tcpmuxHTTPConnectPort": pick("tcpmuxHTTPConnectPort"),
            "kcpBindPort": pick("kcpBindPort"),
            "quicBindPort": pick("quicBindPort"),
            "subdomainHost": pick("subdomainHost"),
            "maxPoolCount": pick("maxPoolCount"),
            "maxPortsPerClient": pick("maxPortsPerClient"),
            "heartbeatTimeout": pick("heartbeatTimeout"),
            "allowPortsStr": pick("allowPortsStr"),
            "tlsForce": pick("tlsForce"),
        },
        "status": {
            "totalTrafficIn": pick("totalTrafficIn"),
            "totalTrafficOut": pick("totalTrafficOut"),
            "curConns": pick("curConns"),
            "clientCounts": pick("clientCounts"),
            "proxyTypeCount": pick("proxyTypeCount"),
        },
    }))
}

/// `POST /api/v2/system/prune?type=offline_proxies|clients`
pub async fn v2_system_prune_handler(
    State(server): State<Arc<Server>>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let prune_type = query
        .get("type")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    match prune_type.as_str() {
        "offline_proxies" => {
            let (cleared, total) = crate::metrics::global_metrics().clear_closed_proxies();
            v2_ok(json!({ "type": "offline_proxies", "cleared": cleared, "total": total }))
                .into_response()
        }
        "clients" => {
            let cleared = server.control_manager.clear_offline_clients().await;
            v2_ok(json!({ "type": "clients", "cleared": cleared, "total": cleared }))
                .into_response()
        }
        _ => v2_error(
            axum::http::StatusCode::BAD_REQUEST,
            "type must be one of offline_proxies, clients",
        ),
    }
}

/// `GET /api/v2/users`
pub async fn v2_users_handler(
    State(server): State<Arc<Server>>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let (page, page_size) = match parse_v2_page(&query) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let q = query.get("q").map(|s| s.to_lowercase()).unwrap_or_default();

    let mut stats: HashMap<String, (i64, i64)> = HashMap::new();
    for client in server.control_manager.get_all_clients().await {
        let entry = stats.entry(client.user).or_insert((0, 0));
        entry.0 += 1;
    }
    for value in collect_all_proxy_stats(&server).await {
        let user = value
            .get("user")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let entry = stats.entry(user).or_insert((0, 0));
        entry.1 += 1;
    }

    let mut items: Vec<Value> = stats
        .into_iter()
        .filter(|(user, _)| q.is_empty() || user.to_lowercase().contains(&q))
        .map(|(user, (clients, proxies))| {
            json!({ "user": user, "clientCount": clients, "proxyCount": proxies })
        })
        .collect();
    items.sort_by_key(|v| {
        v.get("user")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    });

    let total = items.len();
    v2_ok(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": paginate(&items, page, page_size),
    }))
    .into_response()
}

/// `GET /api/v2/clients`
pub async fn v2_clients_handler(
    State(server): State<Arc<Server>>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let (page, page_size) = match parse_v2_page(&query) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let status = match parse_v2_status(query.get("status")) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let user = query.get("user").cloned().unwrap_or_default();
    let client_id = query.get("clientID").cloned().unwrap_or_default();
    let run_id = query.get("runID").cloned().unwrap_or_default();
    let q = query.get("q").map(|s| s.to_lowercase()).unwrap_or_default();

    let mut items: Vec<Value> = server
        .control_manager
        .get_all_clients()
        .await
        .iter()
        .filter(|c| user.is_empty() || c.user == user)
        .filter(|c| client_id.is_empty() || c.client_id == client_id)
        .filter(|c| run_id.is_empty() || c.run_id == run_id)
        .filter(|c| status_matches(c.online, &status))
        .filter(|c| {
            q.is_empty()
                || c.client_id.to_lowercase().contains(&q)
                || c.hostname.to_lowercase().contains(&q)
                || c.client_ip.to_lowercase().contains(&q)
                || c.run_id.to_lowercase().contains(&q)
        })
        .map(build_client_resp)
        .collect();
    items.sort_by_key(|v| {
        (
            v.get("user")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            v.get("clientID")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )
    });

    let total = items.len();
    v2_ok(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": paginate(&items, page, page_size),
    }))
    .into_response()
}

/// `GET /api/v2/clients/{key}`
pub async fn v2_client_detail_handler(
    State(server): State<Arc<Server>>,
    Path(key): Path<String>,
) -> axum::response::Response {
    match server.control_manager.get_client_by_key(&key).await {
        Some(info) => {
            let proxy_count = server
                .proxy_manager
                .proxy_owners
                .read()
                .await
                .values()
                .filter(|run_id| **run_id == info.run_id)
                .count();
            let mut body = build_client_resp(&info);
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "status".to_string(),
                    json!({
                        "phase": if info.online { "online" } else { "offline" },
                        "curConns": info.connected_at.elapsed().as_secs(),
                        "proxyCount": proxy_count,
                    }),
                );
            }
            v2_ok(body).into_response()
        }
        None => v2_error(
            axum::http::StatusCode::NOT_FOUND,
            &format!("client {key} not found"),
        ),
    }
}

/// `GET /api/v2/proxies`
pub async fn v2_proxies_handler(
    State(server): State<Arc<Server>>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let (page, page_size) = match parse_v2_page(&query) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let status = match parse_v2_status(query.get("status")) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let proxy_type = query
        .get("type")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if !proxy_type.is_empty() && !PROXY_TYPES.contains(&proxy_type.as_str()) {
        return v2_error(
            axum::http::StatusCode::BAD_REQUEST,
            &format!("invalid proxy type: {proxy_type}"),
        );
    }
    let user = query.get("user").cloned().unwrap_or_default();
    let client_id = query.get("clientID").cloned().unwrap_or_default();
    let q = query.get("q").map(|s| s.to_lowercase()).unwrap_or_default();

    let mut items: Vec<Value> = collect_all_proxy_stats(&server)
        .await
        .into_iter()
        .filter(|v| {
            let vtype = v
                .get("conf")
                .and_then(|c| c.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("");
            proxy_type.is_empty() || vtype == proxy_type
        })
        .filter(|v| {
            let online = v.get("status").and_then(Value::as_str) == Some("online");
            status_matches(online, &status)
        })
        .filter(|v| user.is_empty() || v.get("user").and_then(Value::as_str).unwrap_or("") == user)
        .filter(|v| {
            client_id.is_empty()
                || v.get("clientID").and_then(Value::as_str).unwrap_or("") == client_id
        })
        .filter(|v| {
            q.is_empty()
                || v.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
        })
        .map(to_v2_proxy_resp)
        .collect();
    items.sort_by_key(|v| {
        (
            v.get("spec")
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            v.get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        )
    });

    let total = items.len();
    v2_ok(json!({
        "total": total,
        "page": page,
        "pageSize": page_size,
        "items": paginate(&items, page, page_size),
    }))
    .into_response()
}

/// `GET /api/v2/proxies/{name}`
pub async fn v2_proxy_detail_handler(
    State(server): State<Arc<Server>>,
    Path(name): Path<String>,
) -> axum::response::Response {
    match collect_all_proxy_stats(&server)
        .await
        .into_iter()
        .find(|v| v.get("name").and_then(Value::as_str) == Some(name.as_str()))
    {
        Some(stats) => v2_ok(to_v2_proxy_resp(stats)).into_response(),
        None => v2_error(axum::http::StatusCode::NOT_FOUND, "no proxy info found"),
    }
}

/// `GET /api/v2/proxies/{name}/traffic`
pub async fn v2_proxy_traffic_handler(Path(name): Path<String>) -> axum::response::Response {
    match traffic_series_of(&name) {
        Some((traffic_in, traffic_out)) => v2_ok(json!({
            "name": name,
            "trafficIn": traffic_in,
            "trafficOut": traffic_out,
        }))
        .into_response(),
        None => v2_error(axum::http::StatusCode::NOT_FOUND, "no proxy info found"),
    }
}

/// v1 的 `ProxyStatsInfo` → v2 的 `V2ProxyResp`（含 `spec` / `status` 两段）
fn to_v2_proxy_resp(v1: Value) -> Value {
    let conf = v1.get("conf").cloned().unwrap_or_else(|| json!({}));
    let proxy_type = conf
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let online = v1.get("status").and_then(Value::as_str) == Some("online");

    let mut spec = json!({
        "type": proxy_type,
        "transport": {
            "useEncryption": conf.get("useEncryption").cloned().unwrap_or(json!(false)),
            "useCompression": conf.get("useCompression").cloned().unwrap_or(json!(false)),
            "bandwidthLimit": conf
                .get("transport")
                .and_then(|t| t.get("bandwidthLimit"))
                .cloned()
                .unwrap_or(json!("")),
        },
    });
    let spec_obj = spec.as_object_mut().expect("literal object");
    if let Some(port) = conf.get("remotePort") {
        spec_obj.insert("remotePort".to_string(), port.clone());
    }
    if let Some(domains) = conf.get("customDomains") {
        spec_obj.insert("customDomains".to_string(), domains.clone());
    }
    if let Some(subdomain) = conf.get("subdomain") {
        spec_obj.insert("subdomain".to_string(), subdomain.clone());
    }
    if let Some(locations) = conf.get("locations") {
        spec_obj.insert("locations".to_string(), locations.clone());
    }
    if let Some(rewrite) = conf.get("hostHeaderRewrite") {
        spec_obj.insert("hostHeaderRewrite".to_string(), rewrite.clone());
    }
    if let Some(multiplexer) = conf.get("multiplexer") {
        spec_obj.insert("multiplexer".to_string(), multiplexer.clone());
    }
    if let Some(route_by) = conf.get("routeByHTTPUser") {
        spec_obj.insert("routeByHTTPUser".to_string(), route_by.clone());
    }
    if let Some(lb) = conf.get("loadBalancer") {
        spec_obj.insert("loadBalancer".to_string(), lb.clone());
    }

    json!({
        "name": v1.get("name").cloned().unwrap_or(Value::Null),
        "user": v1.get("user").cloned().unwrap_or(Value::Null),
        "clientID": v1.get("clientID").cloned().unwrap_or(Value::Null),
        "spec": spec,
        "status": {
            "phase": if online { "online" } else { "offline" },
            "todayTrafficIn": v1.get("todayTrafficIn").cloned().unwrap_or(json!(0)),
            "todayTrafficOut": v1.get("todayTrafficOut").cloned().unwrap_or(json!(0)),
            "curConns": v1.get("curConns").cloned().unwrap_or(json!(0)),
            "lastStartTime": v1.get("lastStartTime").cloned().unwrap_or(json!("")),
            "lastCloseTime": v1.get("lastCloseTime").cloned().unwrap_or(json!("")),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ClientRegistration;
    use rust_frp_config::{AuthConfig, ProxyConfig, ServerConfig, TransportConfig};

    async fn test_server() -> Arc<Server> {
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            vhost_http_port: Some(0),
            vhost_https_port: Some(0),
            auth: AuthConfig {
                method: "token".to_string(),
                token: Some("api-secret".to_string()),
                ..Default::default()
            },
            transport: TransportConfig::default(),
            ..Default::default()
        };
        Arc::new(Server::new(cfg, None).await.expect("server construct"))
    }

    async fn json_body(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn query(pairs: &[(&str, &str)]) -> Query<HashMap<String, String>> {
        Query(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    async fn register_client(server: &Server, run_id: &str) {
        server
            .control_manager
            .add_client(ClientRegistration {
                run_id: run_id.to_string(),
                client_id: "cli-1".to_string(),
                user: "alice".to_string(),
                version: "0.1.0".to_string(),
                hostname: "host-a".to_string(),
                client_ip: "10.0.0.7".to_string(),
                wire_protocol: "v1".to_string(),
                cert_fingerprint: None,
            })
            .await;
    }

    async fn register_proxy(server: &Server, name: &str, run_id: &str) {
        let cfg = ProxyConfig {
            name: name.to_string(),
            r#type: "tcp".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_port: Some(9001),
            use_encryption: true,
            ..Default::default()
        };
        server
            .proxy_manager
            .proxies
            .write()
            .await
            .insert(name.to_string(), cfg);
        server
            .proxy_manager
            .proxy_owners
            .write()
            .await
            .insert(name.to_string(), run_id.to_string());
        // 与真实注册流程一致：代理上线时创建 per-proxy 统计（control.rs 同款调用）
        crate::metrics::global_metrics().register_proxy_stat(name, "tcp", Some(9001));
    }

    #[tokio::test]
    async fn serverinfo_reports_config_and_counts() {
        let server = test_server().await;
        register_client(&server, "run-info").await;
        register_proxy(&server, "api-info-proxy", "run-info").await;

        let value = serverinfo_handler(State(server.clone())).await.0;
        assert_eq!(value["bindPort"], 0);
        assert!(!value["version"].as_str().unwrap_or("").is_empty());
        assert_eq!(value["clientCounts"], 1);
        assert!(value["proxyTypeCount"]["tcp"].as_i64().unwrap_or(0) >= 1);
        assert!(value.get("totalTrafficIn").is_some());
        assert!(value.get("allowPortsStr").is_some());
    }

    #[tokio::test]
    async fn clients_list_filters_and_detail_by_key() {
        let server = test_server().await;
        register_client(&server, "run-cli").await;

        let all = clients_handler(State(server.clone()), query(&[])).await.0;
        assert_eq!(all.len(), 1);
        let key = all[0]["key"].as_str().expect("key").to_string();
        assert_eq!(all[0]["user"], "alice");
        assert_eq!(all[0]["hostname"], "host-a");
        assert_eq!(all[0]["clientIP"], "10.0.0.7");
        assert_eq!(all[0]["online"], true);

        // 过滤：不匹配的用户返回空
        let none = clients_handler(State(server.clone()), query(&[("user", "bob")]))
            .await
            .0;
        assert!(none.is_empty());
        // 过滤：online 状态命中
        let online = clients_handler(State(server.clone()), query(&[("status", "online")]))
            .await
            .0;
        assert_eq!(online.len(), 1);
        let offline = clients_handler(State(server.clone()), query(&[("status", "offline")]))
            .await
            .0;
        assert!(offline.is_empty());

        // 详情：按 key 命中
        let resp = client_detail_handler(State(server.clone()), Path(key.clone())).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["runID"], "run-cli");

        // 详情：未知 key → 404
        let missing = client_detail_handler(State(server.clone()), Path("nope".to_string())).await;
        assert_eq!(missing.status(), axum::http::StatusCode::NOT_FOUND);

        // 离线后仍可在 offline 过滤中查到
        server
            .control_manager
            .remove("run-cli")
            .await
            .expect("remove");
        let offline = clients_handler(State(server.clone()), query(&[("status", "offline")]))
            .await
            .0;
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0]["online"], false);
    }

    #[tokio::test]
    async fn proxy_queries_and_offline_lifecycle() {
        let server = test_server().await;
        register_client(&server, "run-pxy").await;
        register_proxy(&server, "api-pxy-1", "run-pxy").await;

        // /api/proxy/{type}
        let resp = proxy_by_type_handler(State(server.clone()), Path("tcp".to_string())).await;
        let body = json_body(resp).await;
        let list = body["proxies"].as_array().expect("proxies array");
        assert!(list
            .iter()
            .any(|p| p["name"] == "api-pxy-1" && p["clientID"] == "cli-1" && p["user"] == "alice"));

        // 非法类型 → 400
        let bad = proxy_by_type_handler(State(server.clone()), Path("bogus".to_string())).await;
        assert_eq!(bad.status(), axum::http::StatusCode::BAD_REQUEST);

        // /api/proxy/{type}/{name}
        let by_name = proxy_by_type_and_name_handler(
            State(server.clone()),
            Path(("tcp".into(), "api-pxy-1".into())),
        )
        .await;
        assert_eq!(json_body(by_name).await["status"], "online");

        // /api/proxies/{name}
        let detail = proxy_by_name_handler(State(server.clone()), Path("api-pxy-1".into())).await;
        assert_eq!(detail.status(), axum::http::StatusCode::OK);

        // /api/traffic/{name}
        let traffic = proxy_traffic_handler(Path("api-pxy-1".into())).await;
        let traffic_body = json_body(traffic).await;
        assert_eq!(
            traffic_body["trafficIn"].as_array().map(Vec::len),
            Some(crate::metrics::TRAFFIC_HOURS)
        );

        // 记录一条离线历史后：出现在 offline 列表，DELETE 可清理
        let closed_at = rust_frp_util::get_timestamp();
        crate::metrics::global_metrics().record_proxy_closed(crate::metrics::ClosedProxyInfo {
            name: "api-pxy-closed".to_string(),
            proxy_type: "tcp".to_string(),
            user: "alice".to_string(),
            client_id: "cli-1".to_string(),
            remote_port: Some(9002),
            last_start_time: closed_at - 60,
            last_close_time: closed_at,
            traffic_in: 10,
            traffic_out: 20,
        });
        let closed =
            proxy_by_name_handler(State(server.clone()), Path("api-pxy-closed".into())).await;
        let closed_body = json_body(closed).await;
        assert_eq!(closed_body["status"], "offline");
        assert_eq!(closed_body["todayTrafficIn"], 10);
        // 上线/下线时间按**本地时区**渲染（此前是 UTC，比本地时间早 8 小时）
        let expected_close = rust_frp_util::localtime::format_local_datetime(closed_at);
        assert_eq!(
            closed_body["lastCloseTime"].as_str(),
            Some(expected_close.as_str())
        );
        assert_eq!(
            closed_body["lastStartTime"].as_str().map(str::len),
            Some(19),
            "expect YYYY-MM-DD HH:MM:SS: {closed_body}"
        );

        // DELETE 需要 status=offline
        let bad_delete = delete_proxies_handler(query(&[("status", "online")])).await;
        assert_eq!(bad_delete.status(), axum::http::StatusCode::BAD_REQUEST);
        let ok_delete = delete_proxies_handler(query(&[("status", "offline")])).await;
        assert_eq!(ok_delete.status(), axum::http::StatusCode::OK);
        let after =
            proxy_by_name_handler(State(server.clone()), Path("api-pxy-closed".into())).await;
        assert_eq!(after.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn v2_envelope_pagination_and_prune() {
        let server = test_server().await;
        register_client(&server, "run-v2").await;
        register_proxy(&server, "api-v2-1", "run-v2").await;

        // system/info：信封 + config/status 两段
        let info = v2_system_info_handler(State(server.clone())).await.0;
        assert_eq!(info["code"], 200);
        assert_eq!(info["msg"], "success");
        assert!(info["data"]["config"]["bindPort"].is_number());
        assert!(info["data"]["status"]["proxyTypeCount"].is_object());

        // proxies：分页信封
        let proxies = v2_proxies_handler(
            State(server.clone()),
            query(&[("page", "1"), ("pageSize", "1")]),
        )
        .await;
        let body = json_body(proxies).await;
        assert_eq!(body["code"], 200);
        assert!(body["data"]["total"].as_u64().unwrap_or(0) >= 1);
        assert!(body["data"]["items"].as_array().map(Vec::len).unwrap_or(0) <= 1);

        // pageSize 越界 → 400
        let bad_page =
            v2_proxies_handler(State(server.clone()), query(&[("pageSize", "9999")])).await;
        assert_eq!(bad_page.status(), axum::http::StatusCode::BAD_REQUEST);

        // status 非法 → 400
        let bad_status =
            v2_clients_handler(State(server.clone()), query(&[("status", "zzz")])).await;
        assert_eq!(bad_status.status(), axum::http::StatusCode::BAD_REQUEST);

        // clients 详情（含 status 段）
        let clients = v2_clients_handler(State(server.clone()), query(&[])).await;
        let clients_body = json_body(clients).await;
        let key = clients_body["data"]["items"][0]["key"]
            .as_str()
            .expect("key")
            .to_string();
        let detail = v2_client_detail_handler(State(server.clone()), Path(key)).await;
        let detail_body = json_body(detail).await;
        assert_eq!(detail_body["data"]["status"]["phase"], "online");

        // users 聚合
        let users = v2_users_handler(State(server.clone()), query(&[])).await;
        let users_body = json_body(users).await;
        assert!(users_body["data"]["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|u| u["user"] == "alice"));

        // proxy 详情 + 流量
        let proxy_detail =
            v2_proxy_detail_handler(State(server.clone()), Path("api-v2-1".into())).await;
        let proxy_body = json_body(proxy_detail).await;
        assert_eq!(proxy_body["data"]["spec"]["type"], "tcp");
        let proxy_traffic = v2_proxy_traffic_handler(Path("api-v2-1".into())).await;
        assert_eq!(proxy_traffic.status(), axum::http::StatusCode::OK);

        // prune：非法 type → 400；offline_proxies / clients 合法
        let bad_prune =
            v2_system_prune_handler(State(server.clone()), query(&[("type", "nope")])).await;
        assert_eq!(bad_prune.status(), axum::http::StatusCode::BAD_REQUEST);
        let prune =
            v2_system_prune_handler(State(server.clone()), query(&[("type", "offline_proxies")]))
                .await;
        let prune_body = json_body(prune).await;
        assert_eq!(prune_body["data"]["type"], "offline_proxies");
        let prune_clients =
            v2_system_prune_handler(State(server.clone()), query(&[("type", "clients")])).await;
        assert_eq!(prune_clients.status(), axum::http::StatusCode::OK);
    }

    #[test]
    fn timestamp_formatting_uses_local_timezone() {
        // 未记录（<= 0）→ 空串，不显示 1970 年
        assert_eq!(format_timestamp(0), "");
        assert_eq!(format_timestamp(-1), "");

        let secs = 1_700_000_000;
        // 与工具层的本地时间实现必须完全一致（只有一份实现，不会各自漂移）
        assert_eq!(
            format_timestamp(secs),
            rust_frp_util::localtime::format_local_datetime(secs)
        );
        // 定长 19 字符：前端按定宽渲染
        assert_eq!(format_timestamp(secs).len(), 19);

        // 回归守护：宿主不在 UTC 时，输出不得再等于 UTC 表示（这正是本次修复的目标）。
        // 确定性断言（各时区/跨天）在 rust_frp_util::localtime 的纯函数用例里。
        if rust_frp_util::localtime::local_offset_secs() != 0 {
            assert_ne!(format_timestamp(secs), "2023-11-14 22:13:20");
            assert_ne!(format_timestamp(1_000_000_000), "2001-09-09 01:46:40");
        }
    }

    #[test]
    fn traffic_series_records_and_bounds() {
        let stat =
            crate::metrics::global_metrics().register_proxy_stat("series-probe", "tcp", None);
        stat.add_bytes(10, 20);
        stat.add_bytes(1, 2);
        let (incoming, outgoing) = stat.traffic_series();
        assert_eq!(incoming.len(), crate::metrics::TRAFFIC_HOURS);
        assert_eq!(outgoing.len(), crate::metrics::TRAFFIC_HOURS);
        assert_eq!(incoming.iter().sum::<u64>(), 11);
        assert_eq!(outgoing.iter().sum::<u64>(), 22);
    }
}
