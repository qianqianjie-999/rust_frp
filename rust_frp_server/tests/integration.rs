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
    let allow: Vec<PortRange> = ports
        .iter()
        .map(|&p| PortRange {
            single: Some(p),
            start: None,
            end: None,
        })
        .collect();
    let mgr = build_manager(Some(2), allow);

    use rust_frp_core::ProxyManager as _;

    // 前两个 TCP 代理成功
    mgr.add_proxy_for_user(tcp_proxy("a1", ports[0]), "alice")
        .await
        .unwrap();
    mgr.add_proxy_for_user(tcp_proxy("a2", ports[1]), "alice")
        .await
        .unwrap();

    // 第三个超出配额被拒绝
    let err = mgr
        .add_proxy_for_user(tcp_proxy("a3", ports[2]), "alice")
        .await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("max_ports_per_user"));

    // 配额按用户隔离：bob 不受 alice 占用影响
    mgr.add_proxy_for_user(tcp_proxy("b1", ports[2]), "bob")
        .await
        .unwrap();

    // 移除后配额释放，可再次添加
    mgr.remove_proxy("a1").await.unwrap();
    mgr.add_proxy_for_user(tcp_proxy("a4", ports[3]), "alice")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_add_proxy_failure_no_residual() {
    let ok_port = free_port();
    let bad_port = free_port(); // 不在 allow_ports 中
    let mgr = build_manager(
        Some(1),
        vec![PortRange {
            single: Some(ok_port),
            start: None,
            end: None,
        }],
    );

    use rust_frp_core::ProxyManager as _;

    // 端口不在白名单 → 启动失败
    let err = mgr
        .add_proxy_for_user(tcp_proxy("bad", bad_port), "alice")
        .await;
    assert!(err.is_err());

    // 修复点：失败后 proxies map 不应残留
    assert!(mgr.get_proxy_status("bad").await.unwrap().is_none());

    // 修复点：配额预占同时回滚，limit=1 下仍可注册一个代理
    mgr.add_proxy_for_user(tcp_proxy("good", ok_port), "alice")
        .await
        .unwrap();
    assert_eq!(
        mgr.get_proxy_status("good").await.unwrap().as_deref(),
        Some("running")
    );
}

#[tokio::test]
async fn test_add_proxy_duplicate_name_rejected() {
    let port = free_port();
    let mgr = build_manager(
        None,
        vec![PortRange {
            single: Some(port),
            start: None,
            end: None,
        }],
    );

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
    let mgr = build_manager(
        Some(1),
        vec![PortRange {
            single: Some(port),
            start: None,
            end: None,
        }],
    );

    use rust_frp_core::ProxyManager as _;

    // TCP 占 1 个配额
    mgr.add_proxy_for_user(tcp_proxy("t1", port), "alice")
        .await
        .unwrap();

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

// ============ P0-3 tls_only / 工作连接 TLS 协商 ============

use rust_frp_server::{classify_work_conn, WorkConnClass};

#[test]
fn test_classify_work_conn_matrix() {
    use WorkConnClass::*;

    // TLS ClientHello（0x16）：服务器有 TLS 证书 → TLS 握手
    assert_eq!(classify_work_conn(0x16, true, false), Tls);
    assert_eq!(classify_work_conn(0x16, true, true), Tls);

    // TLS ClientHello 但服务器未配置 TLS → 无法握手，拒绝
    assert_eq!(classify_work_conn(0x16, false, false), Reject);
    assert_eq!(classify_work_conn(0x16, false, true), Reject);

    // 明文协议：tls_only 下拒绝（防降级），否则放行（兼容旧客户端）
    assert_eq!(classify_work_conn(0x00, false, true), Reject);
    assert_eq!(classify_work_conn(0x00, true, true), Reject);
    assert_eq!(classify_work_conn(0x00, false, false), Plain);
    assert_eq!(classify_work_conn(0x00, true, false), Plain);
}

#[test]
fn test_login_resp_work_conn_tls_backward_compat() {
    // 新版服务端：协商 work_conn_tls = true
    let resp = rust_frp_core::LoginRespMsg {
        version: "0.1.0".to_string(),
        run_id: "rid".to_string(),
        error: String::new(),
        work_conn_tls: true,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"work_conn_tls\":true"));

    // 旧版服务端 JSON 无 work_conn_tls 字段 → serde default = false（保持旧行为）
    let legacy = r#"{"version":"0.1.0","run_id":"rid","error":""}"#;
    let parsed: rust_frp_core::LoginRespMsg = serde_json::from_str(legacy).unwrap();
    assert!(!parsed.work_conn_tls);
}

#[tokio::test]
async fn test_tls_only_requires_tls_config_validation() {
    // 默认配置 + token 认证补全（默认 token method 必须提供 token 才能通过 AuthManager）
    fn base_cfg() -> rust_frp_config::ServerConfig {
        let mut cfg = rust_frp_config::ServerConfig::default();
        cfg.auth.token = Some("test-token".to_string());
        cfg
    }

    // tls_only = true 但 tls 配置缺失 → Server::new 启动报错
    let mut cfg = base_cfg();
    cfg.transport.tls_only = true;
    cfg.transport.tls = None;
    let err = rust_frp_server::Server::new(cfg, None).await.err();
    let msg = err.map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("tls_only"), "unexpected error: {}", msg);

    // tls_only = true 且 tls.enable = false → 同样报错
    let mut cfg = base_cfg();
    cfg.transport.tls_only = true;
    cfg.transport.tls = Some(rust_frp_config::TlsConfig {
        enable: false,
        ..Default::default()
    });
    assert!(rust_frp_server::Server::new(cfg, None).await.is_err());

    // tls_only = true 且 tls.enable = true → 使用内置证书，启动成功
    let mut cfg = base_cfg();
    cfg.transport.tls_only = true;
    cfg.transport.tls = Some(rust_frp_config::TlsConfig {
        enable: true,
        ..Default::default()
    });
    assert!(rust_frp_server::Server::new(cfg, None).await.is_ok());

    // tls_only = false 且无 TLS → 宽松模式，正常启动（兼容旧行为）
    let mut cfg = base_cfg();
    cfg.transport.tls = None;
    assert!(rust_frp_server::Server::new(cfg, None).await.is_ok());
}

// ============ P1-2 group 负载均衡 ============

#[tokio::test]
async fn test_group_registry_join_pick_round_robin() {
    let reg = rust_frp_server::GroupRegistry::default();

    // 首成员 → true（需要绑定监听端口）
    assert!(reg.join("web", "key1", 9000, "web-1").await.unwrap());
    // 后续成员 → false（共享已有监听器）
    assert!(!reg.join("web", "key1", 9000, "web-2").await.unwrap());

    // round-robin：两成员交替命中
    let a = reg.pick(9000).await.unwrap();
    let b = reg.pick(9000).await.unwrap();
    let c = reg.pick(9000).await.unwrap();
    assert_ne!(a, b, "consecutive picks should hit different members");
    assert_eq!(a, c, "round-robin should cycle back to first member");
    let members = ["web-1", "web-2"];
    assert!(members.contains(&a.as_str()) && members.contains(&b.as_str()));
}

#[tokio::test]
async fn test_group_registry_key_mismatch_rejected() {
    let reg = rust_frp_server::GroupRegistry::default();
    reg.join("web", "secret", 9000, "web-1").await.unwrap();
    let err = reg.join("web", "wrong", 9000, "web-2").await.unwrap_err();
    assert!(err.contains("group_key"), "unexpected error: {}", err);
}

#[tokio::test]
async fn test_group_registry_group_port_unique() {
    let reg = rust_frp_server::GroupRegistry::default();
    reg.join("web", "k", 9000, "web-1").await.unwrap();

    // 同组名绑定不同端口 → 拒绝（对齐 frp ErrGroupDifferentPort）
    let err = reg.join("web", "k", 9001, "web-2").await.unwrap_err();
    assert!(err.contains("bound to port"), "unexpected error: {}", err);

    // 同端口被其他组占用 → 拒绝
    let err = reg.join("api", "k", 9000, "api-1").await.unwrap_err();
    assert!(err.contains("already bound by group"), "unexpected error: {}", err);
}

#[tokio::test]
async fn test_group_registry_leave_and_cleanup() {
    let reg = rust_frp_server::GroupRegistry::default();
    reg.join("web", "k", 9000, "web-1").await.unwrap();
    reg.join("web", "k", 9000, "web-2").await.unwrap();

    // web-1 退出：组未空，返回 false
    assert!(!reg.leave(9000, "web-1").await);
    // 流量全部由 web-2 承接
    for _ in 0..4 {
        assert_eq!(reg.pick(9000).await.unwrap(), "web-2");
    }

    // web-2 退出：组空，返回 true；pick 无成员
    assert!(reg.leave(9000, "web-2").await);
    assert_eq!(reg.member_count(9000).await, 0);
    assert!(reg.pick(9000).await.is_none());

    // 组已清理：同组名可绑定新端口
    assert!(reg.join("web", "k", 9001, "web-3").await.unwrap());
}

#[tokio::test]
async fn test_group_proxy_validation_and_shared_lifecycle() {
    let port = free_port();
    let allow = vec![PortRange {
        single: Some(port),
        start: None,
        end: None,
    }];
    let mgr = build_manager(None, allow);
    use rust_frp_core::ProxyManager as _;

    let grouped = |name: &str, group: &str, key: &str| rust_frp_config::ProxyConfig {
        group: Some(group.to_string()),
        group_key: Some(key.to_string()),
        ..tcp_proxy(name, port)
    };

    // 两个成员注册同一端口：首成员绑定，次成员共享（若重复绑定会 AddrInUse 失败）
    mgr.add_proxy(grouped("web-1", "web", "secret")).await.unwrap();
    mgr.add_proxy(grouped("web-2", "web", "secret")).await.unwrap();

    // group_key 不匹配 → 拒绝
    let err = mgr.add_proxy(grouped("web-3", "web", "wrong")).await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("group_key"));

    // group + plugin 互斥
    let mut p = grouped("web-4", "web2", "k");
    p.plugin = Some(rust_frp_config::PluginConfig::default());
    let err = mgr.add_proxy(p).await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("plugin cannot be used together"));

    // 非 TCP 类型不支持 group
    let mut p = grouped("http-1", "web3", "k");
    p.r#type = "http".to_string();
    let err = mgr.add_proxy(p).await;
    assert!(err.is_err());
    assert!(format!("{:?}", err.unwrap_err()).contains("only supported for tcp"));

    // 成员逐个退出：组空后共享监听器释放，端口可被新代理重新绑定
    mgr.remove_proxy("web-1").await.unwrap();
    mgr.remove_proxy("web-2").await.unwrap();
    mgr.add_proxy(grouped("web-new", "web", "secret")).await.unwrap();
}
