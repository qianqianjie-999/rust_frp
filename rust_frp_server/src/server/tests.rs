//! server 模块测试（原 server.rs 末尾的 `#[cfg(test)] mod`）。

use super::*;

#[cfg(test)]
mod p1_plaintext_ws_tests {
    use super::*;

    fn tls(enable: bool, require_client_cert: bool) -> rust_frp_config::TlsConfig {
        rust_frp_config::TlsConfig {
            enable,
            require_client_cert,
            client_ca_file: Some("/etc/frp/ca.crt".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_reject_when_require_client_cert_enabled() {
        // 线上配置：enable = true + require_client_cert = true ⇒ 必须拒绝明文 ws
        assert!(plaintext_ws_must_be_rejected(false, Some(&tls(true, true))));
    }

    #[test]
    fn test_reject_when_tls_only() {
        // 强制 TLS（tls_only = true）：明文 ws 也是明文，必须拒绝
        assert!(plaintext_ws_must_be_rejected(true, Some(&tls(true, false))));
        assert!(plaintext_ws_must_be_rejected(true, None));
    }

    #[test]
    fn test_allow_in_plaintext_deployment() {
        // 未启用 TLS / 仅灰度（require_client_cert = false）时保持原行为，不误伤
        assert!(!plaintext_ws_must_be_rejected(false, None));
        assert!(!plaintext_ws_must_be_rejected(
            false,
            Some(&tls(false, true))
        ));
        assert!(!plaintext_ws_must_be_rejected(
            false,
            Some(&tls(true, false))
        ));
    }
}

#[cfg(test)]
mod vhost_tls_gate_tests {
    use super::*;

    #[test]
    fn disabled_transport_tls_does_not_start_vhost_https() {
        let tls = rust_frp_config::TlsConfig {
            enable: false,
            cert_file: Some("/tmp/cert.pem".to_string()),
            key_file: Some("/tmp/key.pem".to_string()),
            ..Default::default()
        };
        assert!(!should_start_vhost_https(Some(&tls)));
    }
}

#[cfg(test)]
mod graceful_shutdown_tests {
    use super::*;

    #[tokio::test]
    async fn test_wait_for_drain_returns_immediately_when_idle() {
        let metrics = Arc::new(MonitorMetrics::new());
        let server = drain_test_server(metrics);
        let start = std::time::Instant::now();
        assert!(
            server
                .wait_for_drain(std::time::Duration::from_secs(5))
                .await
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_wait_for_drain_waits_until_connections_close() {
        let metrics = Arc::new(MonitorMetrics::new());
        metrics.increment_connections();
        let server = drain_test_server(metrics.clone());

        // 150ms 后连接关闭 → 排空应成功（轮询 100ms 粒度）
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            metrics.decrement_connections();
        });

        assert!(
            server
                .wait_for_drain(std::time::Duration::from_secs(5))
                .await
        );
    }

    #[tokio::test]
    async fn test_wait_for_drain_times_out_with_active_connections() {
        let metrics = Arc::new(MonitorMetrics::new());
        metrics.increment_connections();
        let server = drain_test_server(metrics);

        assert!(
            !server
                .wait_for_drain(std::time::Duration::from_millis(250))
                .await
        );
    }

    /// 构造一个仅用于排空测试的最小 Server（不绑定任何端口）
    fn drain_test_server(metrics: Arc<MonitorMetrics>) -> Server {
        let mut config = rust_frp_config::ServerConfig::default();
        // token 认证必须配置 token，测试用固定值
        config.auth.token = Some("test-token".to_string());
        Server {
            control_manager: Arc::new(ControlManager::new()),
            proxy_manager: Arc::new(ServerProxyManager::new(
                Arc::new(HttpVhostRouter::new()),
                Arc::new(RwLock::new(std::collections::HashMap::new())),
                Arc::new(ControlManager::new()),
                Arc::new(ServerWorkConnManager::new(1)),
                ProxyManagerOptions {
                    allow_ports: Vec::new(),
                    max_ports_per_user: None,
                    custom_domains_allowlist: Vec::new(),
                    tcpmux_port: None,
                    plugin_manager: Arc::new(rust_frp_plugin::server_plugin::Manager::default()),
                },
            )),
            visitor_manager: Arc::new(ServerVisitorManager::new()),
            auth_runtime: Arc::new(RwLock::new(Arc::new(
                AuthManager::new(&config.auth).expect("default auth is valid"),
            ))),
            conn_manager: ConnManager::new(None, 1),
            tcp_listener: None,
            vhost_http_listener: None,
            vhost_https_listener: None,
            work_conn_listener: None,
            web_server: None,
            metrics,
            work_conn_manager: Arc::new(ServerWorkConnManager::new(1)),
            proxy_owners: Arc::new(RwLock::new(std::collections::HashMap::new())),
            stcp_bridge_manager: Arc::new(StcpBridgeManager::new()),
            xtcp_visitors: Arc::new(RwLock::new(std::collections::HashMap::new())),
            config_path: None,
            reload_rx: None,
            reload_tx: None,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            ingress_tasks: Vec::new(),
            plugin_manager: Arc::new(rust_frp_plugin::server_plugin::Manager::default()),
            config,
        }
    }
}
