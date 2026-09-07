use rust_frp_config::PortRange;
use rust_frp_server::{global_metrics, MonitorMetrics, ProxyConnGuard, ServerError};

#[test]
fn test_server_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ServerError>();
}

#[test]
fn test_server_error_display() {
    let err = ServerError::ProxyNotFound("myproxy".to_string());
    assert!(format!("{}", err).contains("myproxy"));

    let err = ServerError::PortNotAllowed(9999);
    assert!(format!("{}", err).contains("9999"));

    let err = ServerError::Other("something went wrong".to_string());
    assert!(format!("{}", err).contains("something went wrong"));
}

#[test]
fn test_server_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
    let server_err: ServerError = io_err.into();
    assert!(format!("{}", server_err).contains("I/O error"));
}

#[test]
fn test_port_range_default() {
    let pr = PortRange::default();
    assert_eq!(pr.single, None);
    assert_eq!(pr.start, None);
    assert_eq!(pr.end, None);
}

// ============ P0-1 Prometheus 指标 ============

#[test]
fn test_render_prometheus_format() {
    let m = MonitorMetrics::new();
    m.increment_connections();
    m.increment_connections();
    m.decrement_connections();
    m.incr_login_successes();
    m.incr_login_failures();
    m.incr_tls_rejects();
    m.incr_work_conn_total();

    let out = m.render_prometheus();

    // HELP/TYPE 行与 counter/gauge 值
    assert!(out.contains("# TYPE frps_uptime_seconds gauge"));
    assert!(out.contains("# TYPE frps_connections_total counter"));
    assert!(out.contains("frps_connections_total 2"));
    assert!(out.contains("frps_connections_current 1"));
    assert!(out.contains("# TYPE frps_login_successes_total counter"));
    assert!(out.contains("frps_login_successes_total 1"));
    assert!(out.contains("frps_login_failures_total 1"));
    assert!(out.contains("frps_tls_rejects_total 1"));
    assert!(out.contains("frps_work_conn_total 1"));
    // 未接线的 bytes 指标保留但恒 0
    assert!(out.contains("frps_traffic_bytes_sent_total 0"));
}

#[test]
fn test_render_prometheus_label_escaping() {
    let m = MonitorMetrics::new();
    // 恶意 proxy name：含引号、反斜杠、换行——必须被转义防止注入
    m.register_proxy_stat("evil\"\\name\ninject", "tcp", Some(6000));

    let out = m.render_prometheus();
    // 原始恶意串不应出现；转义后的串应出现
    assert!(!out.contains("evil\"\\name\ninject"));
    assert!(out.contains("name=\"evil\\\"\\\\name\\ninject\""));
    assert!(
        out.contains("frps_proxy_conns_current{name=\"evil\\\"\\\\name\\ninject\",type=\"tcp\"} 0")
    );
}

#[test]
fn test_proxy_conn_guard_acquire_release() {
    let m = MonitorMetrics::new();
    let stat = m.register_proxy_stat("ssh", "tcp", Some(6000));

    {
        let _g = ProxyConnGuard::acquire(stat.clone());
        let _g2 = ProxyConnGuard::acquire(stat.clone());
        assert_eq!(
            stat.current_conns.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(
            stat.total_conns.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }
    // 全部 drop 后 current 归零,total 保留
    assert_eq!(
        stat.current_conns.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        stat.total_conns.load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    // per-proxy 指标出现在输出中
    let out = m.render_prometheus();
    assert!(out.contains("frps_proxy_conns_current{name=\"ssh\",type=\"tcp\"} 0"));
    assert!(out.contains("frps_proxy_conns_total{name=\"ssh\",type=\"tcp\"} 2"));

    // 注销后不再出现
    m.remove_proxy_stat("ssh");
    let out = m.render_prometheus();
    assert!(!out.contains("frps_proxy_conns_current{name=\"ssh\""));
}

#[test]
fn test_global_metrics_singleton() {
    let a = global_metrics();
    let b = global_metrics();
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}

// ============ P0-2 max_ports_per_user 配额 + add_proxy 回滚 ============

use rust_frp_server::{ControlManager, HttpVhostRouter, ServerProxyManager, ServerWorkConnManager};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 构造测试用 ServerProxyManager
fn build_manager(
    max_ports_per_user: Option<usize>,
    allow_ports: Vec<PortRange>,
) -> ServerProxyManager {
    let auth_config = rust_frp_config::AuthConfig {
        method: "token".to_string(),
        token: Some("test-token".to_string()),
        oidc: None,
    };
    ServerProxyManager::new(
        Arc::new(HttpVhostRouter::new()),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(ControlManager::new()),
        Arc::new(ServerWorkConnManager::new(4)),
        Arc::new(rust_frp_auth::AuthManager::new(&auth_config).unwrap()),
        allow_ports,
        max_ports_per_user,
    )
}

/// 获取一个临时空闲端口（bind 0 后立即释放）
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tcp_proxy(name: &str, port: u16) -> rust_frp_config::ProxyConfig {
    rust_frp_config::ProxyConfig {
        name: name.to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 22,
        remote_port: Some(port),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_max_ports_per_user_quota() {
    let ports: Vec<u16> = (0..4).map(|_| free_port()).collect();
    let allow: Vec<PortRange> = ports.iter().map(|&p| PortRange { single: Some(p), start: None, end: None }).collect();
    let mgr = build_manager(Some(2), allow);

    use rust_frp_core::ProxyManager as _;

    // 前两个 TCP 代理成功
    mgr.add_proxy_for_user(tcp_proxy("a1", ports[0]), "alice").await.unwrap();
    mgr.add_proxy_for_user(tcp_proxy("a2", ports[1]), "alice").await.unwrap();

    // 第三个超出配额被拒绝
    let err = mgr.add_proxy_for_user(tcp_proxy("a3", ports[2]), "alice").await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("max_ports_per_user"));

    // 配额按用户隔离：bob 不受 alice 占用影响
    mgr.add_proxy_for_user(tcp_proxy("b1", ports[2]), "bob").await.unwrap();

    // 移除后配额释放，可再次添加
    mgr.remove_proxy("a1").await.unwrap();
    mgr.add_proxy_for_user(tcp_proxy("a4", ports[3]), "alice").await.unwrap();
}

#[tokio::test]
async fn test_add_proxy_failure_no_residual() {
    let ok_port = free_port();
    let bad_port = free_port(); // 不在 allow_ports 中
    let mgr = build_manager(Some(1), vec![PortRange { single: Some(ok_port), start: None, end: None }]);

    use rust_frp_core::ProxyManager as _;

    // 端口不在白名单 → 启动失败
    let err = mgr.add_proxy_for_user(tcp_proxy("bad", bad_port), "alice").await;
    assert!(err.is_err());

    // 修复点：失败后 proxies map 不应残留
    assert!(mgr.get_proxy_status("bad").await.unwrap().is_none());

    // 修复点：配额预占同时回滚，limit=1 下仍可注册一个代理
    mgr.add_proxy_for_user(tcp_proxy("good", ok_port), "alice").await.unwrap();
    assert_eq!(
        mgr.get_proxy_status("good").await.unwrap().as_deref(),
        Some("running")
    );
}

#[tokio::test]
async fn test_add_proxy_duplicate_name_rejected() {
    let port = free_port();
    let mgr = build_manager(None, vec![PortRange { single: Some(port), start: None, end: None }]);

    use rust_frp_core::ProxyManager as _;

    mgr.add_proxy(tcp_proxy("dup", port)).await.unwrap();
    // 同名重复注册返回错误，而不是覆盖旧条目
    let err = mgr.add_proxy(tcp_proxy("dup", port)).await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("already exists"));
}

#[tokio::test]
async fn test_http_proxy_not_counted_in_quota() {
    let port = free_port();
    let mgr = build_manager(Some(1), vec![PortRange { single: Some(port), start: None, end: None }]);

    use rust_frp_core::ProxyManager as _;

    // TCP 占 1 个配额
    mgr.add_proxy_for_user(tcp_proxy("t1", port), "alice").await.unwrap();

    // HTTP 不占用端口配额，limit=1 下仍可注册
    let http = rust_frp_config::ProxyConfig {
        name: "h1".to_string(),
        r#type: "http".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 80,
        custom_domains: Some(vec!["test.example.com".to_string()]),
        ..Default::default()
    };
    mgr.add_proxy_for_user(http, "alice").await.unwrap();
}
