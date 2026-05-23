use rust_frp_config::{
    ServerConfig, ClientConfig, ProxyConfig, AuthConfig, TransportConfig,
    TlsConfig, PortRange, WebServerConfig, OidcConfig,
};
use rust_frp_auth::AuthManager;
use rust_frp_core::Message;
use rust_frp_util::{get_timestamp, rand_id};

fn make_server_config(port: u16) -> ServerConfig {
    PortRange::default(); // ensure default impl exists
    ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port: port,
        work_conn_port: Some(port + 1000),
        vhost_http_port: None,
        vhost_https_port: None,
        allow_ports: vec![
            PortRange { single: Some(port + 1), start: None, end: None },
            PortRange { start: Some(port + 100), end: Some(port + 200), single: None },
        ],
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some("test_token".to_string()),
            ..Default::default()
        },
        transport: TransportConfig {
            tls: Some(TlsConfig { enable: false, ..Default::default() }),
            ..Default::default()
        },
        web_server: WebServerConfig { port: 0, ..Default::default() },
        ..ServerConfig::default()
    }
}

fn make_client_config(server_port: u16) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port,
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some("test_token".to_string()),
            ..Default::default()
        },
        transport: TransportConfig {
            tls: Some(TlsConfig { enable: false, ..Default::default() }),
            ..Default::default()
        },
        proxies: vec![
            ProxyConfig {
                name: "test_tcp".to_string(),
                r#type: "tcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 0,
                remote_port: Some(server_port + 1),
                ..Default::default()
            },
        ],
        ..ClientConfig::default()
    }
}

#[test]
fn test_server_config_construction() {
    let config = make_server_config(19300);
    assert_eq!(config.bind_port, 19300);
    assert_eq!(config.auth.token, Some("test_token".to_string()));
    assert!(config.allow_ports.len() == 2);
}

#[test]
fn test_client_config_construction() {
    let config = make_client_config(19300);
    assert_eq!(config.server_port, 19300);
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].name, "test_tcp");
}

#[test]
fn test_auth_token_verification() {
    let config = AuthConfig {
        method: "token".to_string(),
        token: Some("test_token".to_string()),
        ..Default::default()
    };
    let manager = AuthManager::new(&config);
    assert!(manager.is_ok());
}

#[test]
fn test_message_login_serialization_roundtrip() {
    let msg = Message::Login(rust_frp_core::LoginMsg {
        arch: "amd64".to_string(),
        os: "linux".to_string(),
        hostname: "test".to_string(),
        pool_count: 10,
        user: "admin".to_string(),
        client_id: "c1".to_string(),
        version: "1.0".to_string(),
        timestamp: get_timestamp(),
        run_id: rand_id(16),
        token: "secret".to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    });
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::Login(l) => {
            assert_eq!(l.hostname, "test");
            assert_eq!(l.token, "secret");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_port_range_configuration() {
    let port = PortRange {
        single: Some(8080),
        start: None,
        end: None,
    };
    assert_eq!(port.single, Some(8080));

    let range = PortRange {
        start: Some(10000),
        end: Some(20000),
        single: None,
    };
    assert_eq!(range.start, Some(10000));
    assert_eq!(range.end, Some(20000));
}

#[tokio::test]
async fn test_hsmac_sign_roundtrip() {
    let config = AuthConfig {
        method: "token".to_string(),
        token: Some("my_secure_token".to_string()),
        ..Default::default()
    };
    let manager = AuthManager::new(&config).unwrap();
    let sign_key = manager.generate_work_conn_sign_key("run_abc").await.unwrap();
    assert!(!sign_key.is_empty());

    let sign_key2 = manager.generate_work_conn_sign_key("run_abc").await.unwrap();
    assert_eq!(sign_key, sign_key2);
}

#[test]
fn test_config_transport_defaults() {
    let transport = TransportConfig::default();
    assert_eq!(transport.protocol, "tcp");
    assert_eq!(transport.pool_count, 10);
    assert!(transport.tcp_mux);
}

#[test]
fn test_config_tls_defaults() {
    let tls = TlsConfig::default();
    assert!(tls.enable);
    assert!(!tls.force);
}

#[test]
fn test_config_auth_defaults() {
    let auth = AuthConfig::default();
    assert_eq!(auth.method, "token");
}

#[test]
fn test_all_error_types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<rust_frp_auth::AuthError>();
    assert_send_sync::<rust_frp_core::CoreError>();
    assert_send_sync::<rust_frp_config::ConfigError>();
    assert_send_sync::<rust_frp_net::NetError>();
    assert_send_sync::<rust_frp_util::UtilError>();
    assert_send_sync::<rust_frp_client::ClientError>();
}

#[test]
fn test_server_and_client_defaults() {
    let server = ServerConfig::default();
    assert_eq!(server.bind_addr, "0.0.0.0");
    assert!(server.allow_ports.is_empty());

    let client = ClientConfig::default();
    assert_eq!(client.server_addr, "127.0.0.1");
    assert!(client.proxies.is_empty());
}

// ============================================================
// P1 功能测试：WebSocket / STCP / XTCP
// ============================================================

#[test]
fn test_websocket_proxy_config() {
    let proxy = ProxyConfig {
        name: "ws_test".to_string(),
        r#type: "websocket".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 8080,
        remote_port: Some(9000),
        ..Default::default()
    };
    assert_eq!(proxy.r#type, "websocket");
    assert_eq!(proxy.name, "ws_test");
    assert_eq!(proxy.remote_port, Some(9000));
}

#[test]
fn test_stcp_proxy_config() {
    let proxy = ProxyConfig {
        name: "stcp_test".to_string(),
        r#type: "stcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 22,
        secret_key: Some("my_secret_key".to_string()),
        ..Default::default()
    };
    assert_eq!(proxy.r#type, "stcp");
    assert!(proxy.remote_port.is_none());
    assert_eq!(proxy.secret_key, Some("my_secret_key".to_string()));
}

#[test]
fn test_xtcp_proxy_config() {
    let proxy = ProxyConfig {
        name: "xtcp_test".to_string(),
        r#type: "xtcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 3389,
        secret_key: Some("xtcp_secret".to_string()),
        ..Default::default()
    };
    assert_eq!(proxy.r#type, "xtcp");
    assert_eq!(proxy.local_port, 3389);
    assert_eq!(proxy.secret_key.as_deref(), Some("xtcp_secret"));
}

#[test]
fn test_stcp_visitor_config() {
    let visitor = rust_frp_config::VisitorConfig {
        name: "visit_ssh".to_string(),
        r#type: "stcp".to_string(),
        server_name: "ssh_proxy".to_string(),
        secret_key: Some("my_secret_key".to_string()),
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 9000,
        transport: None,
    };
    assert_eq!(visitor.r#type, "stcp");
    assert_eq!(visitor.server_name, "ssh_proxy");
    assert_eq!(visitor.bind_port, 9000);
    assert_eq!(visitor.secret_key.as_deref(), Some("my_secret_key"));
}

#[test]
fn test_xtcp_visitor_config() {
    let visitor = rust_frp_config::VisitorConfig {
        name: "visit_rdp".to_string(),
        r#type: "xtcp".to_string(),
        server_name: "rdp_proxy".to_string(),
        secret_key: Some("xtcp_secret".to_string()),
        bind_addr: "127.0.0.1".to_string(),
        bind_port: 13389,
        transport: None,
    };
    assert_eq!(visitor.r#type, "xtcp");
    assert_eq!(visitor.server_name, "rdp_proxy");
    assert_eq!(visitor.bind_port, 13389);
}

#[test]
fn test_stcp_visitor_msg_serialization() {
    let msg = Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
        proxy_name: "ssh".to_string(),
        run_id: "run123".to_string(),
        timestamp: 1700000000,
        sign_key: "abc_sign".to_string(),
    });
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::StcpVisitor(m) => {
            assert_eq!(m.proxy_name, "ssh");
            assert_eq!(m.run_id, "run123");
            assert_eq!(m.sign_key, "abc_sign");
        }
        _ => panic!("expected StcpVisitor, got wrong variant"),
    }
}

#[test]
fn test_xtcp_nat_info_msg_serialization() {
    let msg = Message::XtcpNatInfo(rust_frp_core::XtcpNatInfoMsg {
        proxy_name: "rdp".to_string(),
        run_id: "run456".to_string(),
        nat_type: "full_cone".to_string(),
        local_addr: "192.168.1.5:3389".to_string(),
        public_addr: "1.2.3.4:12345".to_string(),
    });
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::XtcpNatInfo(m) => {
            assert_eq!(m.proxy_name, "rdp");
            assert_eq!(m.nat_type, "full_cone");
            assert_eq!(m.public_addr, "1.2.3.4:12345");
        }
        _ => panic!("expected XtcpNatInfo, got wrong variant"),
    }
}

#[test]
fn test_xtcp_hole_punch_msg_serialization() {
    let msg = Message::XtcpHolePunch(rust_frp_core::XtcpHolePunchMsg {
        proxy_name: "rdp".to_string(),
        from_run_id: "run_a".to_string(),
        to_run_id: "run_b".to_string(),
        peer_local_addr: "10.0.0.1:3389".to_string(),
        peer_public_addr: "5.6.7.8:54321".to_string(),
    });
    let json = serde_json::to_string(&msg).unwrap();
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::XtcpHolePunch(m) => {
            assert_eq!(m.from_run_id, "run_a");
            assert_eq!(m.to_run_id, "run_b");
            assert_eq!(m.peer_local_addr, "10.0.0.1:3389");
        }
        _ => panic!("expected XtcpHolePunch, got wrong variant"),
    }
}

#[test]
fn test_client_config_with_stcp_xtcp_proxies() {
    let config = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some("test123".to_string()),
            ..Default::default()
        },
        transport: Default::default(),
        proxies: vec![
            ProxyConfig {
                name: "ssh".to_string(),
                r#type: "stcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 22,
                secret_key: Some("key1".to_string()),
                ..Default::default()
            },
            ProxyConfig {
                name: "rdp".to_string(),
                r#type: "xtcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 3389,
                secret_key: Some("key2".to_string()),
                ..Default::default()
            },
        ],
        visitors: vec![
            rust_frp_config::VisitorConfig {
                name: "v_ssh".to_string(),
                r#type: "stcp".to_string(),
                server_name: "ssh".to_string(),
                secret_key: Some("key1".to_string()),
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 9000,
                transport: None,
            },
            rust_frp_config::VisitorConfig {
                name: "v_rdp".to_string(),
                r#type: "xtcp".to_string(),
                server_name: "rdp".to_string(),
                secret_key: Some("key2".to_string()),
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 13389,
                transport: None,
            },
        ],
        ..Default::default()
    };

    assert_eq!(config.proxies.len(), 2);
    assert_eq!(config.visitors.len(), 2);

    let stcp = &config.proxies[0];
    assert_eq!(stcp.r#type, "stcp");
    assert_eq!(stcp.secret_key.as_deref(), Some("key1"));
    assert!(stcp.remote_port.is_none());

    let xtcp = &config.proxies[1];
    assert_eq!(xtcp.r#type, "xtcp");
    assert_eq!(xtcp.secret_key.as_deref(), Some("key2"));

    let v1 = &config.visitors[0];
    assert_eq!(v1.r#type, "stcp");
    assert_eq!(v1.server_name, "ssh");

    let v2 = &config.visitors[1];
    assert_eq!(v2.r#type, "xtcp");
    assert_eq!(v2.server_name, "rdp");
}

#[test]
fn test_proxy_config_secret_key_is_optional() {
    let proxy = ProxyConfig {
        name: "no_secret".to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 80,
        remote_port: Some(8080),
        ..Default::default()
    };
    assert!(proxy.secret_key.is_none());
}

// ============================================================
// P2 功能测试：健康检查 + 热重载
// ============================================================

#[test]
fn test_health_check_config_tcp() {
    let config = rust_frp_config::HealthCheckConfig {
        r#type: "tcp".to_string(),
        interval_seconds: 30,
        timeout_seconds: 5,
        max_failed: 3,
        path: None,
    };
    assert_eq!(config.r#type, "tcp");
    assert_eq!(config.interval_seconds, 30);
    assert_eq!(config.timeout_seconds, 5);
    assert_eq!(config.max_failed, 3);
}

#[test]
fn test_health_check_config_http() {
    let config = rust_frp_config::HealthCheckConfig {
        r#type: "http".to_string(),
        interval_seconds: 10,
        timeout_seconds: 3,
        max_failed: 5,
        path: Some("/health".to_string()),
    };
    assert_eq!(config.r#type, "http");
    assert_eq!(config.path, Some("/health".to_string()));
}

#[test]
fn test_proxy_with_health_check() {
    let proxy = ProxyConfig {
        name: "web_with_hc".to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 8080,
        remote_port: Some(9000),
        health_check: Some(rust_frp_config::HealthCheckConfig {
            r#type: "http".to_string(),
            interval_seconds: 10,
            timeout_seconds: 3,
            max_failed: 3,
            path: Some("/healthz".to_string()),
        }),
        ..Default::default()
    };
    assert_eq!(proxy.name, "web_with_hc");
    assert!(proxy.health_check.is_some());
    let hc = proxy.health_check.as_ref().unwrap();
    assert_eq!(hc.r#type, "http");
    assert_eq!(hc.path.as_deref(), Some("/healthz"));
}

#[test]
fn test_health_checker_creation() {
    let proxy = ProxyConfig {
        name: "test_proxy".to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 3000,
        remote_port: Some(8000),
        health_check: Some(rust_frp_config::HealthCheckConfig {
            r#type: "tcp".to_string(),
            interval_seconds: 30,
            timeout_seconds: 5,
            max_failed: 3,
            path: None,
        }),
        ..Default::default()
    };
    let _checker = rust_frp_client::HealthChecker::new(proxy.clone());
    assert!(!proxy.name.is_empty());
}

#[test]
fn test_hot_reload_config_merge() {
    let old_config = make_client_config(17000);
    let mut new_config = old_config.clone();
    new_config.proxies.push(ProxyConfig {
        name: "new_proxy".to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 9090,
        remote_port: Some(9091),
        ..Default::default()
    });

    assert_eq!(new_config.proxies.len(), 2);
    assert_eq!(old_config.proxies.len(), 1);
    assert_eq!(new_config.proxies[1].name, "new_proxy");
}

#[test]
fn test_hot_reload_auth_change() {
    let old_config = make_client_config(17000);
    let mut new_config = old_config.clone();
    new_config.auth.token = Some("new_token".to_string());

    assert_eq!(old_config.auth.token, Some("test_token".to_string()));
    assert_eq!(new_config.auth.token, Some("new_token".to_string()));
}

#[test]
fn test_hot_reload_server_config() {
    let old_config = make_server_config(19000);
    let mut new_config = old_config.clone();
    new_config.allow_ports.push(PortRange {
        single: Some(19999),
        start: None,
        end: None,
    });

    assert_eq!(old_config.allow_ports.len(), 2);
    assert_eq!(new_config.allow_ports.len(), 3);
    assert_eq!(new_config.allow_ports[2].single, Some(19999));
}

#[test]
fn test_reload_channel_creation() {
    let (tx, rx) = tokio::sync::mpsc::channel::<()>(16);
    // Channel should be usable
    assert!(!tx.is_closed());
    assert!(rx.is_empty());
}

#[tokio::test]
async fn test_reload_signal_delivery() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
    tx.send(()).await.unwrap();
    let result = rx.recv().await;
    assert!(result.is_some());
}

#[tokio::test]
async fn test_reload_multiple_signals() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
    for _ in 0..3 {
        tx.send(()).await.unwrap();
    }
    for _ in 0..3 {
        let result = rx.recv().await;
        assert!(result.is_some());
    }
    assert!(rx.is_empty());
}

// ============================================================
// P3: Bandwidth Limit Tests
// ============================================================

#[test]
fn test_bandwidth_limit_parse_kb() {
    let rate = rust_frp_util::parse_bandwidth_limit("500KB");
    assert!(rate.is_some());
    assert_eq!(rate.unwrap(), 500.0 * 1024.0);
}

#[test]
fn test_bandwidth_limit_parse_mb() {
    let rate = rust_frp_util::parse_bandwidth_limit("10MB");
    assert!(rate.is_some());
    assert_eq!(rate.unwrap(), 10.0 * 1024.0 * 1024.0);
}

#[test]
fn test_bandwidth_limit_parse_gb() {
    let rate = rust_frp_util::parse_bandwidth_limit("1GB");
    assert!(rate.is_some());
    assert_eq!(rate.unwrap(), 1024.0 * 1024.0 * 1024.0);
}

#[test]
fn test_bandwidth_limit_parse_no_unit() {
    let rate = rust_frp_util::parse_bandwidth_limit("1024");
    assert!(rate.is_some());
    assert_eq!(rate.unwrap(), 1024.0);
}

#[test]
fn test_bandwidth_limit_parse_empty() {
    assert_eq!(rust_frp_util::parse_bandwidth_limit(""), None);
}

#[test]
fn test_bandwidth_limit_parse_case_insensitive() {
    let rate1 = rust_frp_util::parse_bandwidth_limit("10mb");
    let rate2 = rust_frp_util::parse_bandwidth_limit("10MB");
    assert_eq!(rate1, rate2);
}

#[test]
fn test_bandwidth_limit_proxy_config() {
    let config = ProxyConfig {
        name: "rate_limited_proxy".to_string(),
        r#type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 8080,
        remote_port: Some(9090),
        bandwidth_limit: Some("5MB".to_string()),
        ..Default::default()
    };
    assert_eq!(config.bandwidth_limit, Some("5MB".to_string()));
    let rate = rust_frp_util::parse_bandwidth_limit(config.bandwidth_limit.as_deref().unwrap());
    assert_eq!(rate, Some(5.0 * 1024.0 * 1024.0));
}

#[test]
fn test_bandwidth_limit_transport_global_config() {
    let config = TransportConfig {
        bandwidth_limit: Some("20MB".to_string()),
        ..Default::default()
    };
    assert_eq!(config.bandwidth_limit, Some("20MB".to_string()));
}

// ============================================================
// P3: OIDC Authentication Tests
// ============================================================

#[test]
fn test_oidc_config_default() {
    let oidc_config = OidcConfig::default();
    assert_eq!(oidc_config.issuer, "");
    assert_eq!(oidc_config.audience, "");
}

#[test]
fn test_auth_config_oidc_method() {
    let config = AuthConfig {
        method: "oidc".to_string(),
        token: None,
        oidc: Some(OidcConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "frp-app".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "my-secret".to_string(),
            token_endpoint_url: "https://auth.example.com/token".to_string(),
        }),
    };
    assert_eq!(config.method, "oidc");
    assert!(config.oidc.is_some());
    assert_eq!(config.oidc.as_ref().unwrap().issuer, "https://auth.example.com");
}

#[test]
fn test_oidc_auth_manager_creation() {
    let config = AuthConfig {
        method: "oidc".to_string(),
        token: None,
        oidc: Some(OidcConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "frp-app".to_string(),
            client_id: "my-client".to_string(),
            client_secret: "my-secret".to_string(),
            token_endpoint_url: "https://auth.example.com/token".to_string(),
        }),
    };
    let result = AuthManager::new(&config);
    assert!(result.is_ok());
}

#[test]
fn test_oidc_auth_manager_missing_config() {
    let config = AuthConfig {
        method: "oidc".to_string(),
        token: None,
        oidc: None,
    };
    let result = AuthManager::new(&config);
    assert!(result.is_err());
}
