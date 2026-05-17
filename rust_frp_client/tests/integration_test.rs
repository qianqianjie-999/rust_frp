use rust_frp_config::{
    ServerConfig, ClientConfig, ProxyConfig, AuthConfig, TransportConfig,
    TlsConfig, PortRange, WebServerConfig,
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
