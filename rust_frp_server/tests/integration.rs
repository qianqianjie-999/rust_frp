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
