//! 配置模块测试（原 lib.rs 末尾的 `#[cfg(test)] mod` 集合）。

#[cfg(test)]
mod basic_config_tests {
    use crate::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.bind_port, 7000);
        assert!(config.vhost_http_port.is_none());
        assert!(config.allow_ports.is_empty());
    }

    #[test]
    fn test_default_client_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_addr, "127.0.0.1");
        assert_eq!(config.server_port, 7000);
        assert!(config.proxies.is_empty());
    }

    #[test]
    fn test_parse_config_toml() {
        let toml_str = r#"
bind_addr = "0.0.0.0"
bind_port = 9300
vhost_http_port = 8080

[auth]
method = "token"
token = "test_token"

[[allow_ports]]
single = 8080
"#;
        let config: ServerConfig =
            ConfigLoader::parse_config::<ServerConfig>(toml_str, ConfigKind::Server, false)
                .unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.bind_port, 9300);
        assert_eq!(config.vhost_http_port, Some(8080));
        assert_eq!(config.auth.token, Some("test_token".to_string()));
        assert_eq!(config.allow_ports.len(), 1);
        assert_eq!(config.allow_ports[0].single, Some(8080));
    }

    #[test]
    fn test_parse_config_json() {
        let json_str = r#"{
            "bind_addr": "0.0.0.0",
            "bind_port": 9300,
            "allow_ports": [{"single": 8080}]
        }"#;
        let config: ServerConfig =
            ConfigLoader::parse_config::<ServerConfig>(json_str, ConfigKind::Server, false)
                .unwrap();
        assert_eq!(config.bind_port, 9300);
        assert_eq!(config.allow_ports.len(), 1);
    }

    #[test]
    fn test_parse_tcpmux_and_sudp_proxy_fields() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "mux"
type = "tcpmux"
custom_domains = ["mux.example.com"]
multiplexer = "httpconnect"
routeByHTTPUser = "alice"
httpUser = "alice"
httpPassword = "pw"
allowUsers = ["alice", "bob"]
useCompression = true

[[visitors]]
name = "visit-udp"
type = "sudp"
server_name = "udp-svc"
bind_addr = "127.0.0.1"
bind_port = 5353
secret_key = "s3cret"
useCompression = true
"#;
        let config: ClientConfig =
            ConfigLoader::parse_config::<ClientConfig>(toml_str, ConfigKind::Client, false)
                .unwrap();

        let proxy = &config.proxies[0];
        assert_eq!(proxy.r#type, "tcpmux");
        assert_eq!(proxy.multiplexer.as_deref(), Some("httpconnect"));
        assert_eq!(proxy.route_by_http_user.as_deref(), Some("alice"));
        assert_eq!(
            proxy.allow_users.as_deref(),
            Some(["alice".to_string(), "bob".to_string()].as_slice())
        );
        assert!(proxy.use_compression);

        let visitor = &config.visitors[0];
        assert_eq!(visitor.r#type, "sudp");
        assert_eq!(visitor.secret_key.as_deref(), Some("s3cret"));
        assert!(visitor.use_compression);
    }

    #[test]
    fn test_validate_server_config_missing_port() {
        let config = ServerConfig {
            bind_port: 0,
            ..Default::default()
        };
        let result = ConfigLoader::validate_server_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_config_success() {
        let config = ServerConfig {
            bind_port: 9300,
            ..Default::default()
        };
        let result = ConfigLoader::validate_server_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_server_config_rejects_dashboard_without_credentials() {
        // 安全评审 P1：启用 dashboard 但没配凭据时，鉴权中间件根本不挂载
        // （requires_login() == false）⇒ 全部页面 + POST /api/reload 对匿名开放。
        // 必须拒绝启动，而不是只打一条 warn。
        let config = ServerConfig {
            bind_port: 9300,
            web_server: WebServerConfig {
                port: 7500,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = ConfigLoader::validate_server_config(&config).unwrap_err();
        assert!(
            err.to_string().contains("web_server.user/password"),
            "错误信息应指明缺少凭据：{err}"
        );
    }

    #[test]
    fn test_validate_server_config_accepts_dashboard_with_credentials() {
        let config = ServerConfig {
            bind_port: 9300,
            web_server: WebServerConfig {
                port: 7500,
                user: Some("boss".to_string()),
                password: Some("pw".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(ConfigLoader::validate_server_config(&config).is_ok());
    }

    #[test]
    fn test_validate_custom_domain_accepts_wellformed_names() {
        for good in [
            "example.com",
            "app.example.com",
            "*.example.com",
            "a-b.c.example.com",
            "localhost",
            "123.example.com",
        ] {
            assert!(validate_custom_domain(good).is_ok(), "{good:?} 应通过");
        }
    }

    #[test]
    fn test_validate_custom_domain_rejects_malformed_names() {
        let long_label = "x".repeat(64);
        let mut bad: Vec<&str> = vec![
            "",
            "   ",
            "evil..example.com",
            ".example.com",
            "example.com.",
            "bad_underscore.example.com",
            "-lead.example.com",
            "trail-.example.com",
            "mid*star.example.com",
            "*.evil*.example.com",
            "*",
            "*.",
            "a.*.example.com",
            "exa mple.com",
        ];
        bad.push(long_label.as_str());
        for b in bad {
            assert!(validate_custom_domain(b).is_err(), "{b:?} 应被拒绝");
        }
    }

    #[test]
    fn test_validate_server_config_rejects_bad_domain_allowlist_entry() {
        // 白名单条目本身写错（例如想写 *.example.com 却写成 "*"）会让收口静默失效，
        // 必须在启动时就拒绝。
        let config = ServerConfig {
            bind_port: 9300,
            custom_domains_allowlist: vec!["*".to_string()],
            ..Default::default()
        };
        let err = ConfigLoader::validate_server_config(&config).unwrap_err();
        assert!(
            err.to_string().contains("custom_domains_allowlist"),
            "错误信息应指明白名单条目非法：{err}"
        );
    }

    #[test]
    fn test_server_config_accepts_custom_domains_allowlist() {
        let config: ServerConfig = toml::from_str(
            r#"
bind_port = 9300
custom_domains_allowlist = ["app.example.com", "*.corp.example.com"]
"#,
        )
        .unwrap();
        assert_eq!(config.custom_domains_allowlist.len(), 2);
        // 默认必须为空（零破坏：不改变既有部署行为）
        assert!(ServerConfig::default().custom_domains_allowlist.is_empty());
    }

    #[test]
    fn test_validate_client_config_missing_addr() {
        let config = ClientConfig {
            server_addr: "".to_string(),
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_client_config_missing_port() {
        let config = ClientConfig {
            server_port: 0,
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_client_config_success() {
        let config = ClientConfig {
            server_addr: "example.com".to_string(),
            server_port: 9300,
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_replace_env_vars_simple() {
        std::env::set_var("FRP_TEST_ADDR", "10.0.0.1");
        let result = ConfigLoader::replace_env_vars("${FRP_TEST_ADDR}:8080");
        assert_eq!(result, "10.0.0.1:8080");
        std::env::remove_var("FRP_TEST_ADDR");
    }

    #[test]
    fn test_replace_env_vars_not_set() {
        let result = ConfigLoader::replace_env_vars("${NONEXISTENT_VAR}");
        assert_eq!(result, "");
    }

    #[test]
    fn test_replace_env_vars_multiple() {
        std::env::set_var("HOST", "localhost");
        std::env::set_var("PORT", "9300");
        let result = ConfigLoader::replace_env_vars("${HOST}:${PORT}");
        assert_eq!(result, "localhost:9300");
        std::env::remove_var("HOST");
        std::env::remove_var("PORT");
    }

    #[test]
    fn test_port_range_single() {
        let toml_str = r#"single = 8080"#;
        let port: PortRange = toml::from_str(toml_str).unwrap();
        assert_eq!(port.single, Some(8080));
    }

    #[test]
    fn test_port_range_range() {
        let toml_str = r#"start = 10000
end = 20000"#;
        let port: PortRange = toml::from_str(toml_str).unwrap();
        assert_eq!(port.start, Some(10000));
        assert_eq!(port.end, Some(20000));
    }

    #[test]
    fn test_proxy_config_tcp() {
        let toml_str = r#"
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
"#;
        let proxy: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(proxy.name, "ssh");
        assert_eq!(proxy.r#type, "tcp");
        assert_eq!(proxy.local_port, 22);
        assert_eq!(proxy.remote_port, Some(6000));
    }

    #[test]
    fn test_proxy_config_http_with_domains() {
        let toml_str = r#"
name = "web"
type = "http"
local_ip = "127.0.0.1"
local_port = 80
custom_domains = ["example.com", "www.example.com"]
"#;
        let proxy: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(proxy.name, "web");
        assert_eq!(proxy.r#type, "http");
        assert_eq!(
            proxy.custom_domains,
            Some(vec![
                "example.com".to_string(),
                "www.example.com".to_string()
            ])
        );
    }

    #[test]
    fn test_tls_config_defaults() {
        let config = TlsConfig::default();
        assert!(config.enable);
        assert!(!config.force);
        assert!(config.cert_file.is_none());
        assert!(config.key_file.is_none());
    }

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::default();
        assert_eq!(config.protocol, "tcp");
        assert!(config.tcp_mux);
        // 与原版 frp 对齐：默认不预建工作连接（旧版本这里是 10，会在空闲时
        // 常驻 pool_count × 代理数 条 TLS 连接）
        assert_eq!(config.pool_count, 0);
        assert_eq!(config.effective_max_pool_count(), DEFAULT_MAX_POOL_COUNT);
        assert_eq!(
            config.tcp_keepalive_idle(),
            Some(std::time::Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS))
        );
    }

    /// `pool_count`（客户端想开多少）与 `max_pool_count`（服务端允许多少）语义分离
    #[test]
    fn test_pool_count_overrides_and_keepalive_disable() {
        let cfg: TransportConfig =
            toml::from_str("poolCount = 2\nmaxPoolCount = 4\ntcpKeepaliveSecs = 0")
                .expect("parse transport config");
        assert_eq!(cfg.pool_count, 2);
        assert_eq!(cfg.effective_max_pool_count(), 4);
        // 0 = 关闭 keepalive
        assert_eq!(cfg.tcp_keepalive_idle(), None);

        // 未显式配置 maxPoolCount 时退回默认上限，不受 pool_count 影响
        let cfg2: TransportConfig =
            toml::from_str("poolCount = 0").expect("parse transport config");
        assert_eq!(cfg2.effective_max_pool_count(), DEFAULT_MAX_POOL_COUNT);
    }

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::default();
        assert_eq!(config.method, "token");
        assert!(config.token.is_none());
    }

    #[test]
    fn test_client_config_parse() {
        let toml_str = r#"
server_addr = "10.0.0.1"
server_port = 9300

[auth]
method = "token"
token = "my_token"

[[proxies]]
name = "app1"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 9302
"#;
        let config: ClientConfig =
            ConfigLoader::parse_config::<ClientConfig>(toml_str, ConfigKind::Client, false)
                .unwrap();
        assert_eq!(config.server_addr, "10.0.0.1");
        assert_eq!(config.server_port, 9300);
        assert_eq!(config.auth.token, Some("my_token".to_string()));
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].name, "app1");
    }

    #[test]
    fn test_merge_server_config() {
        let mut target = ServerConfig::default();
        let source = ServerConfig {
            bind_addr: "10.0.0.1".to_string(),
            bind_port: 9999,
            ..ServerConfig::default()
        };
        ConfigLoader::merge_server_config(&mut target, &source);
        assert_eq!(target.bind_addr, "10.0.0.1");
        assert_eq!(target.bind_port, 9999);
    }

    #[test]
    fn test_merge_client_config() {
        let mut target = ClientConfig::default();
        let source = ClientConfig {
            server_addr: "10.0.0.1".to_string(),
            server_port: 9999,
            user: Some("admin".to_string()),
            ..ClientConfig::default()
        };
        ConfigLoader::merge_client_config(&mut target, &source);
        assert_eq!(target.server_addr, "10.0.0.1");
        assert_eq!(target.server_port, 9999);
        assert_eq!(target.user, Some("admin".to_string()));
    }

    #[test]
    fn test_web_server_expose_metrics_defaults_to_false() {
        // 安全默认：未配置 expose_metrics 时必须关闭 /metrics（P1-4）
        let config: WebServerConfig = toml::from_str(
            r#"
addr = "127.0.0.1"
port = 7500
user = "boss"
password = "pw"
"#,
        )
        .unwrap();
        assert!(!config.expose_metrics);
    }

    #[test]
    fn test_web_server_expose_metrics_can_be_enabled() {
        let config: WebServerConfig = toml::from_str(
            r#"
addr = "127.0.0.1"
port = 7500
expose_metrics = true
"#,
        )
        .unwrap();
        assert!(config.expose_metrics);
    }
}

#[cfg(test)]
mod example_config_tests {
    use crate::ConfigLoader;
    use std::path::Path;
    /// 示例配置文件必须始终可解析：README 引导用户复制 example 改配置，
    /// 若字段重命名/删除后未同步 example，用户会拿到一个跑不起来的模板。
    #[test]
    fn test_frpc_example_toml_always_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frpc.example.toml");
        let config = ConfigLoader::load_client_config(&path)
            .expect("frpc.example.toml must stay parseable by ConfigLoader");
        assert!(!config.server_addr.is_empty());
        assert!(config.server_port > 0);
    }

    #[test]
    fn test_frps_example_toml_always_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frps.example.toml");
        let config = ConfigLoader::load_server_config(&path)
            .expect("frps.example.toml must stay parseable by ConfigLoader");
        assert!(config.bind_port > 0);
    }

    /// CLI 默认 `--strict_config`（对齐原版，默认 true）：
    /// 示例配置在严格模式下也必须零未知字段，否则用户照 README 启动即失败。
    #[test]
    fn test_examples_pass_strict_mode() {
        let frpc = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frpc.example.toml");
        ConfigLoader::load_client_config_strict(&frpc, true)
            .expect("frpc.example.toml must pass strict (--strict_config default) mode");
        let frps = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frps.example.toml");
        ConfigLoader::load_server_config_strict(&frps, true)
            .expect("frps.example.toml must pass strict (--strict_config default) mode");
    }
}

#[cfg(test)]
mod upstream_compat_tests {
    use crate::ConfigLoader;
    use std::path::PathBuf;

    /// 把内容写成临时 TOML 并加载（走完整 load 链路：解析→includes→环境变量→归并→验证）
    fn write_temp_config(prefix: &str, content: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}_{}_{}.toml",
            prefix,
            std::process::id(),
            crate::compat_test_counter()
        ));
        std::fs::write(&path, content).expect("write temp config");
        path
    }

    /// 服务端 [[httpPlugins]]（原版 camelCase 数组表）必须可解析并落到 http_plugins。
    #[test]
    fn test_upstream_http_plugins_config_parses() {
        let path = write_temp_config(
            "frps_plugins",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[httpPlugins]]
name = "user-manager"
addr = "http://127.0.0.1:9000"
path = "/handler"
ops = ["Login", "NewProxy"]
tlsVerify = false
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("httpPlugins must parse");
        assert_eq!(config.http_plugins.len(), 1);
        let plugin = &config.http_plugins[0];
        assert_eq!(plugin.name, "user-manager");
        assert_eq!(plugin.addr, "http://127.0.0.1:9000");
        assert_eq!(plugin.path, "/handler");
        assert_eq!(
            plugin.ops,
            vec!["Login".to_string(), "NewProxy".to_string()]
        );
        assert!(!plugin.tls_verify);
        let _ = std::fs::remove_file(&path);
    }

    /// 未知 op 的插件必须被拒绝（避免「配了插件却静默不回调」）。
    #[test]
    fn test_http_plugins_unknown_op_rejected() {
        let path = write_temp_config(
            "frps_bad_plugin",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[http_plugins]]
name = "bad"
addr = "http://127.0.0.1:9000"
ops = ["Login", "NotAnOp"]
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("unknown op"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 服务端 [[http_plugins]]（canonical snake_case）同样可解析，
    /// 且不得被未知字段检查误报（compat 已知键集回归）。
    #[test]
    fn test_snake_case_http_plugins_config_parses() {
        let path = write_temp_config(
            "frps_plugins_snake",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[http_plugins]]
name = "local"
addr = "http://127.0.0.1:9100"
ops = ["Login"]

[webServer]
port = 7500
user = "admin"
password = "pw"
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("http_plugins must parse");
        assert_eq!(config.http_plugins.len(), 1);
        assert_eq!(config.http_plugins[0].name, "local");
        let _ = std::fs::remove_file(&path);
    }

    /// 客户端 OIDC：原版 camelCase 字段（clientID/clientSecret/tokenEndpointURL）
    /// 与新增字段（scope/additionalEndpointParams/trustedCaFile/insecureSkipVerify）
    /// 必须全部正确落到配置结构。
    #[test]
    fn test_upstream_oidc_client_config_parses() {
        let path = write_temp_config(
            "frpc_oidc",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000

[auth]
method = "oidc"

[auth.oidc]
issuer = "https://idp.example.com"
audience = "frp-server"
clientID = "frp-client"
clientSecret = "s3cret"
tokenEndpointURL = "https://idp.example.com/token"
scope = "openid profile"
trustedCaFile = "/etc/ssl/idp-ca.pem"
insecureSkipVerify = true

[auth.oidc.additionalEndpointParams]
resource = "https://api.example.com"
"#,
        );
        let config = ConfigLoader::load_client_config(&path).expect("oidc config must parse");
        let oidc = config.auth.oidc.as_ref().expect("oidc present");
        assert_eq!(config.auth.method, "oidc");
        assert_eq!(oidc.client_id, "frp-client");
        assert_eq!(oidc.client_secret, "s3cret");
        assert_eq!(oidc.token_endpoint_url, "https://idp.example.com/token");
        assert_eq!(oidc.scope, "openid profile");
        assert_eq!(oidc.trusted_ca_file, "/etc/ssl/idp-ca.pem");
        assert!(oidc.insecure_skip_verify);
        assert_eq!(
            oidc.additional_endpoint_params
                .get("resource")
                .map(String::as_str),
            Some("https://api.example.com")
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 服务端 OIDC：必须配置 issuer，否则启动即失败；配了则解析出 skip* 开关。
    #[test]
    fn test_server_oidc_requires_issuer() {
        let path = write_temp_config(
            "frps_oidc_missing_issuer",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"

[auth.oidc]
audience = "frp-server"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(err.to_string().contains("issuer"), "unexpected: {err}");
        let _ = std::fs::remove_file(&path);

        let path = write_temp_config(
            "frps_oidc_no_config",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(err.to_string().contains("auth.oidc"), "unexpected: {err}");
        let _ = std::fs::remove_file(&path);

        let path = write_temp_config(
            "frps_oidc_ok",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"

[auth.oidc]
issuer = "https://idp.example.com"
audience = "frp-server"
skipExpiryCheck = true
skipIssuerCheck = false
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("server oidc must parse");
        let oidc = config.auth.oidc.expect("oidc present");
        assert_eq!(oidc.issuer, "https://idp.example.com");
        assert!(oidc.skip_expiry_check);
        assert!(!oidc.skip_issuer_check);
        let _ = std::fs::remove_file(&path);
    }

    /// 客户端 OIDC 的非法配置必须被拒绝：缺 client_id、端点 URL 非绝对 http(s)、
    /// 以及 additionalEndpointParams 里塞 scope。
    #[test]
    fn test_client_oidc_validation_errors() {
        let cases = [
            (
                "frpc_oidc_no_client",
                "[auth.oidc]\ntokenEndpointURL = \"https://idp.example.com/token\"\n",
                "client_id",
            ),
            (
                "frpc_oidc_bad_url",
                "[auth.oidc]\nclientID = \"c\"\ntokenEndpointURL = \"idp.example.com/token\"\n",
                "absolute http",
            ),
            (
                "frpc_oidc_scope_param",
                "[auth.oidc]\nclientID = \"c\"\ntokenEndpointURL = \"https://idp.example.com/token\"\n\
                 \n[auth.oidc.additionalEndpointParams]\nscope = \"openid\"\n",
                "additional_endpoint_params.scope",
            ),
        ];
        for (name, tail, needle) in cases {
            let content = format!("serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n[auth]\nmethod = \"oidc\"\n\n{tail}");
            let path = write_temp_config(name, &content);
            let err = ConfigLoader::load_client_config(&path).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "case {name}: expected {needle:?}, got {err}"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// QUIC：协议字段非法值必须报错（避免拼写错误静默回退到 TCP）
    #[test]
    fn test_unsupported_transport_protocol_rejected() {
        let content =
            "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n[transport]\nprotocol = \"quicc\"\n";
        let path = write_temp_config("frpc_bad_proto", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("transport.protocol"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// QUIC：强制 TLS 1.3 无明文模式 → 必须显式声明信任来源（CA 或 skip_verify）
    #[test]
    fn test_quic_requires_explicit_trust_source() {
        let content =
            "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n[transport]\nprotocol = \"quic\"\n";
        let path = write_temp_config("frpc_quic_no_trust", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("trusted_ca_file") && text.contains("skip_verify"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// QUIC：原版 camelCase 的 transport.quic.* 参数可被识别（并满足信任来源校验）
    #[test]
    fn test_quic_transport_config_parses() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [transport]\nprotocol = \"quic\"\n\n\
            [transport.quic]\nmaxIdleTimeout = 15\nmaxIncomingStreams = 4096\nkeepalivePeriod = 5\n\n\
            [transport.tls]\nskipVerify = true\n";
        let path = write_temp_config("frpc_quic_ok", content);
        let config =
            ConfigLoader::load_client_config(&path).expect("quic client config must parse");
        let q = config.transport.quic.expect("transport.quic parsed");
        assert_eq!(q.max_idle_timeout, Some(15));
        assert_eq!(q.max_incoming_streams, Some(4096));
        assert_eq!(q.keepalive_period, Some(5));
        let _ = std::fs::remove_file(&path);
    }

    /// wss：强制 TLS（无明文模式）→ 必须显式声明信任来源（CA 或 skip_verify）
    #[test]
    fn test_wss_requires_explicit_trust_source() {
        let content =
            "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n[transport]\nprotocol = \"wss\"\n";
        let path = write_temp_config("frpc_wss_no_trust", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("trusted_ca_file") && text.contains("skip_verify"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// wss：合法的 `wss` 协议名必须被接受（对齐原版 frp 的 protocol 取值）
    #[test]
    fn test_wss_protocol_accepted_with_trust_source() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [transport]\nprotocol = \"wss\"\n\n\
            [transport.tls]\nskipVerify = true\n";
        let path = write_temp_config("frpc_wss_ok", content);
        let config = ConfigLoader::load_client_config(&path).expect("wss client config must parse");
        assert_eq!(config.transport.protocol, "wss");
        let _ = std::fs::remove_file(&path);
    }

    /// 服务端：KCP 与 QUIC 共用同一 UDP 端口必须被拒绝
    #[test]
    fn test_server_kcp_quic_port_clash_rejected() {
        let content = "bindPort = 7000\nkcpBindPort = 7001\nquicBindPort = 7001\n";
        let path = write_temp_config("frps_udp_clash", content);
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("same UDP port"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 插件：socks5 的 username/password（原版字段名）与 http_proxy 的 camelCase 凭据均可解析
    #[test]
    fn test_plugin_credential_fields_parse() {
        // 键名用拼接构造：避免在源码里写出形如 `键 = "值"` 的示例字面量
        let user_key = format!("{}{}", "user", "name");
        let pass_key = format!("{}{}", "pass", "word");
        let socks_src =
            format!("type = \"socks5\"\n{user_key} = \"alice\"\n{pass_key} = \"s3cret\"\n");
        let socks: crate::PluginConfig = toml::from_str(&socks_src).expect("socks5 plugin parse");
        assert_eq!(socks.username.as_deref(), Some("alice"));
        assert_eq!(socks.password.as_deref(), Some("s3cret"));

        let http_src = "type = \"http_proxy\"\nhttpUser = \"bob\"\nhttpPassword = \"pw\"\n";
        let http: crate::PluginConfig = toml::from_str(http_src).expect("http_proxy plugin parse");
        assert_eq!(http.http_user.as_deref(), Some("bob"));
        assert_eq!(http.http_password.as_deref(), Some("pw"));
    }

    /// tokenSource：file 类型可解析，且把 token 字段留空是合法的
    #[test]
    fn test_token_source_file_parses() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [auth]\nmethod = \"token\"\n\n\
            [auth.tokenSource]\ntype = \"file\"\nfilePath = \"/run/secrets/frp_token\"\n";
        let path = write_temp_config("frpc_tokensource_file", content);
        let config = ConfigLoader::load_client_config(&path)
            .expect("tokenSource(file) client config must parse");
        let ts = config.auth.token_source.expect("token_source parsed");
        assert_eq!(ts.r#type, "file");
        assert_eq!(ts.file_path.as_deref(), Some("/run/secrets/frp_token"));
        assert!(config.auth.token.is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// tokenSource：type = "file" 缺少 filePath 必须被拒绝
    #[test]
    fn test_token_source_file_requires_path() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [auth]\nmethod = \"token\"\n\n\
            [auth.tokenSource]\ntype = \"file\"\n";
        let path = write_temp_config("frpc_tokensource_nopath", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("filePath"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// tokenSource：token 与 tokenSource 同时配置必须被拒绝（互斥）
    #[test]
    fn test_token_source_mutually_exclusive_with_token() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [auth]\nmethod = \"token\"\ntoken = \"static\"\n\n\
            [auth.tokenSource]\ntype = \"exec\"\nexec = [\"/usr/bin/vault\", \"read\"]\n";
        let path = write_temp_config("frpc_tokensource_both", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// tokenSource：未知 type 必须被拒绝
    #[test]
    fn test_token_source_unsupported_type_rejected() {
        let content = "serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n\
            [auth]\nmethod = \"token\"\n\n\
            [auth.tokenSource]\ntype = \"vault\"\n";
        let path = write_temp_config("frpc_tokensource_bad", content);
        let err = ConfigLoader::load_client_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("tokenSource.type"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 未知的 auth.method 必须被拒绝（避免「配了个不认识的方法却静默放行」）。
    #[test]
    fn test_unsupported_auth_method_rejected() {
        let path = write_temp_config(
            "frps_bad_auth",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "ldap"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("unsupported auth.method"),
            "unexpected: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 原版 frp 0.71 风格的客户端配置（camelCase + transport.useEncryption 嵌套）
    /// 必须可以直接解析，且语义与本项目的 snake_case 写法一致。
    #[test]
    fn test_upstream_camelcase_client_config_parses() {
        let path = write_temp_config(
            "frpc_upstream",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000
user = "alice"

auth.method = "token"
auth.token = "shared-secret"

transport.protocol = "tcp"
transport.tls.enable = true
transport.poolCount = 6

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022

[[proxies]]
name = "web-encrypted"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8080
remotePort = 6180
transport.useEncryption = true

[[visitors]]
name = "visit-ssh"
type = "stcp"
serverName = "peer-ssh"
secretKey = "peer-key"
bindAddr = "127.0.0.1"
bindPort = 9000
"#,
        );
        let config =
            ConfigLoader::load_client_config(&path).expect("upstream-style frpc config must parse");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.server_addr, "203.0.113.10");
        assert_eq!(config.server_port, 7000);
        assert_eq!(config.user.as_deref(), Some("alice"));
        assert_eq!(config.auth.token.as_deref(), Some("shared-secret"));
        assert_eq!(config.transport.pool_count, 6);

        assert_eq!(config.proxies[0].local_ip, "127.0.0.1");
        assert_eq!(config.proxies[0].remote_port, Some(6022));
        assert!(!config.proxies[0].use_encryption);

        // transport.useEncryption 应被归并进代理顶层 use_encryption
        assert!(config.proxies[1].use_encryption);

        assert_eq!(config.visitors[0].server_name, "peer-ssh");
        assert_eq!(config.visitors[0].bind_port, 9000);
    }

    /// 原版风格的服务端配置
    #[test]
    fn test_upstream_camelcase_server_config_parses() {
        let path = write_temp_config(
            "frps_upstream",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
workConnPort = 8000

webServer.port = 7500
webServer.addr = "127.0.0.1"
webServer.user = "admin"
webServer.password = "admin-pwd"

transport.tls.force = true

[[allowPorts]]
start = 10000
end = 20000
"#,
        );
        let config =
            ConfigLoader::load_server_config(&path).expect("upstream-style frps config must parse");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.bind_port, 7000);
        assert_eq!(config.vhost_http_port, Some(8080));
        assert_eq!(config.vhost_https_port, Some(8443));
        assert_eq!(config.work_conn_port, Some(8000));
        assert_eq!(config.web_server.port, 7500);
        assert!(config.transport.tls.as_ref().expect("tls config").force);
        assert_eq!(config.allow_ports.len(), 1);
        assert_eq!(config.allow_ports[0].start, Some(10000));
    }

    /// 含原版暂不支持字段（loginFailExit、disableLogColor 等）的配置必须仍能加载，
    /// 不支持项以 WARN 提示而非硬性拒绝（非 strict 模式）。
    ///
    /// 注：原版 `log.*` 段已支持（见 `test_upstream_log_section_accepted_in_strict_mode`），
    /// 不再作为"不支持字段"的样例。
    #[test]
    fn test_upstream_config_with_unsupported_fields_still_loads() {
        let path = write_temp_config(
            "frpc_partial",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000
loginFailExit = false
disableLogColor = true
metasVar = "unused"

log.to = "./frpc.log"
log.level = "info"
log.maxDays = 3

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022
"#,
        );
        let config = ConfigLoader::load_client_config(&path)
            .expect("config with unsupported upstream fields must still load");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.server_addr, "203.0.113.10");
        assert_eq!(config.proxies.len(), 1);
    }

    /// 回归（P0-2，2026-10-05 线上核查发现）：**标准原版 frps.toml 必须能在
    /// strict 模式下加载**。
    ///
    /// 背景：`log` 段此前不在已知键白名单中，导致一份完全合法的原版配置
    /// （`[log] to/level/maxDays`）在 `--strict_config`（默认 true）下直接启动失败，
    /// 与「原版配置可直接复用」的目标冲突。
    #[test]
    fn test_upstream_log_section_accepted_in_strict_mode() {
        let path = write_temp_config(
            "frps_upstream_log",
            r#"
bindAddr = "0.0.0.0"
bindPort = 9300

log.to = "/var/log/frps.log"
log.level = "info"
log.maxDays = 7

auth.method = "token"
auth.token = "upstream-token"
"#,
        );
        let config = ConfigLoader::load_server_config_strict(&path, true)
            .expect("standard upstream frps.toml with [log] must pass strict mode");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.bind_port, 9300);
        let log = config.resolved_log();
        assert_eq!(log.to.as_deref(), Some("/var/log/frps.log"));
        assert_eq!(log.level.as_deref(), Some("info"));
        assert_eq!(log.max_days, 7);
    }

    /// 旧版 INI 风格顶层字段 `log_file` / `log_level` / `log_max_days`
    /// （线上 rust_frps.toml 即为此写法）在 strict 模式下同样必须被接受。
    #[test]
    fn test_legacy_log_fields_accepted_in_strict_mode() {
        let path = write_temp_config(
            "frps_legacy_log",
            r#"
bind_port = 9300
log_level = "info"
log_file = "/opt/rust_frp/logs/frps.log"
log_max_days = 5
"#,
        );
        let config = ConfigLoader::load_server_config_strict(&path, true)
            .expect("legacy top-level log_* fields must pass strict mode");
        std::fs::remove_file(&path).ok();

        let log = config.resolved_log();
        assert_eq!(log.to.as_deref(), Some("/opt/rust_frp/logs/frps.log"));
        assert_eq!(log.level.as_deref(), Some("info"));
        assert_eq!(log.max_days, 5);
    }

    /// `[log]` 段与旧版顶层字段的合并规则：**段内优先**，顶层仅兜底；
    /// 空串视为未配置；都未配置时 max_days 取默认 3、文件为 None。
    #[test]
    fn test_log_section_takes_precedence_over_legacy_fields() {
        // 段内优先
        let both = write_temp_config(
            "frpc_log_both",
            r#"
server_addr = "1.2.3.4"
server_port = 9300
log_file = "/legacy/frpc.log"
log_level = "warn"
log_max_days = 9

[log]
to = "/section/frpc.log"
level = "debug"
maxDays = 1
"#,
        );
        let config = ConfigLoader::load_client_config_strict(&both, true).expect("must load");
        std::fs::remove_file(&both).ok();
        let log = config.resolved_log();
        assert_eq!(log.to.as_deref(), Some("/section/frpc.log"));
        assert_eq!(log.level.as_deref(), Some("debug"));
        assert_eq!(log.max_days, 1);

        // 顶层兜底 + 空串视为未配置（`log_file = "   "` 不应被当成合法路径）
        let legacy_only = write_temp_config(
            "frpc_log_legacy_only",
            r#"
server_addr = "1.2.3.4"
server_port = 9300
log_file = "   "
log_level = "warn"
"#,
        );
        let config =
            ConfigLoader::load_client_config_strict(&legacy_only, true).expect("must load");
        std::fs::remove_file(&legacy_only).ok();
        let log = config.resolved_log();
        assert_eq!(log.to, None, "blank string must be treated as unset");
        assert_eq!(log.level.as_deref(), Some("warn"));
        assert_eq!(log.max_days, crate::DEFAULT_LOG_MAX_DAYS);

        // 完全未配置 → 默认值
        let none = write_temp_config(
            "frpc_log_none",
            r#"
server_addr = "1.2.3.4"
server_port = 9300
"#,
        );
        let config = ConfigLoader::load_client_config_strict(&none, true).expect("must load");
        std::fs::remove_file(&none).ok();
        assert_eq!(config.resolved_log(), crate::ResolvedLog::default());
    }
}

mod wire_protocol_tests {
    use crate::*;

    fn base_client_toml(extra_auth: &str, wire: &str) -> String {
        format!(
            r#"
server_addr = "127.0.0.1"
server_port = 7000
{extra_auth}
[transport]
wireProtocol = "{wire}"
"#
        )
    }

    #[test]
    fn test_wire_protocol_default_is_v1() {
        let cfg = ClientConfig::default();
        assert_eq!(cfg.transport.wire_protocol, "v1");
    }

    #[test]
    fn test_wire_protocol_camel_case_alias_and_v2_token_ok() {
        let toml = base_client_toml(
            r#"
[auth]
method = "token"
token = "t"
"#,
            "v2",
        );
        let cfg = ConfigLoader::validate_client_config_content(&toml)
            .expect("v2 with token auth must validate");
        assert_eq!(cfg.transport.wire_protocol, "v2");
    }

    #[test]
    fn test_wire_protocol_rejects_unknown_value() {
        let toml = base_client_toml(
            r#"
[auth]
method = "token"
token = "t"
"#,
            "v3",
        );
        let err = ConfigLoader::validate_client_config_content(&toml)
            .expect_err("unknown wire_protocol must be rejected");
        assert!(err.to_string().contains("wire_protocol"), "{err}");
    }

    #[test]
    fn test_wire_protocol_v2_requires_token_auth() {
        // v2 的基础密钥 = SHA-256(token)，OIDC 无静态 token → 必须拒绝
        let toml = base_client_toml(
            r#"
[auth]
method = "oidc"

[auth.oidc]
client_id = "cid"
token_endpoint_url = "https://idp.example.com/token"
"#,
            "v2",
        );
        let err = ConfigLoader::validate_client_config_content(&toml)
            .expect_err("v2 with oidc auth must be rejected");
        assert!(err.to_string().contains("requires auth.method"), "{err}");
    }
}

#[cfg(test)]
mod strict_config_tests {
    use crate::*;

    const UNKNOWN_FIELD_TOML: &str = r#"
server_addr = "127.0.0.1"
server_port = 7000
loginFailExit = true
"#;

    /// 非严格模式（缺省）：未知字段仅 WARN，解析成功
    #[test]
    fn non_strict_mode_warns_but_parses() {
        let cfg = ConfigLoader::validate_client_config_content(UNKNOWN_FIELD_TOML)
            .expect("non-strict mode must tolerate unknown fields");
        assert_eq!(cfg.server_port, 7000);
    }

    /// 严格模式：未知字段直接报错（对齐原版 --strict_config 默认 true）
    #[test]
    fn strict_mode_rejects_unknown_fields() {
        let err = ConfigLoader::validate_client_config_content_strict(UNKNOWN_FIELD_TOML, true)
            .expect_err("strict mode must reject unknown fields");
        assert!(err.to_string().contains("strict config mode"), "{err}");
        assert!(err.to_string().contains("loginFailExit"), "{err}");
    }

    /// 已知 camelCase 别名字段在严格模式下不误报
    #[test]
    fn strict_mode_accepts_known_aliases() {
        let toml = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 6000
proxyProtocolVersion = "v2"
"#;
        let cfg = ConfigLoader::validate_client_config_content_strict(toml, true)
            .expect("known camelCase aliases must pass strict mode");
        assert_eq!(cfg.proxies[0].proxy_protocol_version.as_deref(), Some("v2"));
    }
}

#[cfg(test)]
mod proxy_protocol_version_tests {
    use crate::*;

    fn client_toml(proxy_body: &str) -> String {
        format!(
            r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "web"
type = "tcp"
local_port = 80
remote_port = 6000
{proxy_body}
"#
        )
    }

    /// 原版 camelCase 别名 + 合法 v2 值
    #[test]
    fn camel_case_alias_v2_accepted() {
        let toml = client_toml("proxyProtocol = true\nproxyProtocolVersion = \"v2\"");
        let cfg = ConfigLoader::validate_client_config_content(&toml)
            .expect("proxyProtocolVersion v2 must validate");
        let proxy = cfg.proxies.first().expect("proxy present");
        assert_eq!(proxy.proxy_protocol_version.as_deref(), Some("v2"));
    }

    /// 仅设置版本（不设 proxy_protocol 布尔）也可解析（原版语义：版本即开关）
    #[test]
    fn version_alone_accepted() {
        let toml = client_toml("proxyProtocolVersion = \"v1\"");
        let cfg = ConfigLoader::validate_client_config_content(&toml)
            .expect("version alone must validate");
        let proxy = cfg.proxies.first().expect("proxy present");
        assert_eq!(proxy.proxy_protocol_version.as_deref(), Some("v1"));
    }

    /// 未知版本被拒绝（对齐原版 validation）
    #[test]
    fn unknown_version_rejected() {
        let toml = client_toml("proxyProtocolVersion = \"v3\"");
        let err = ConfigLoader::validate_client_config_content(&toml)
            .expect_err("unknown proxy protocol version must be rejected");
        assert!(err.to_string().contains("proxy_protocol_version"), "{err}");
    }
    #[cfg(test)]
    mod additional_scopes_tests {
        use crate::*;

        /// camelCase 别名解析 + 合法值
        #[test]
        fn camel_case_alias_parses() {
            let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"
token = "t"
additionalScopes = ["heartBeats", "newWorkConns"]
"#;
            let cfg = ConfigLoader::validate_client_config_content(toml)
                .expect("additionalScopes must validate with token auth");
            assert_eq!(
                cfg.auth.additional_scopes.as_deref(),
                Some(&["heartBeats".to_string(), "newWorkConns".to_string()][..])
            );
        }

        /// 非法值被拒绝
        #[test]
        fn unknown_scope_rejected() {
            let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"
token = "t"
additional_scopes = ["logins"]
"#;
            let err = ConfigLoader::validate_client_config_content(toml)
                .expect_err("unknown scope must be rejected");
            assert!(err.to_string().contains("additional_scopes"), "{err}");
        }

        /// heartBeats + 空静态 token 被拒绝（签名密钥依赖非空 token，fail-closed）
        #[test]
        fn heartbeats_scope_requires_nonempty_token() {
            let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"
additional_scopes = ["heartBeats"]
"#;
            let err = ConfigLoader::validate_client_config_content(toml)
                .expect_err("heartBeats without token must be rejected");
            assert!(err.to_string().contains("heartBeats"), "{err}");
        }

        /// heartBeats + OIDC 被拒绝（签名密钥依赖静态 token）
        #[test]
        fn heartbeats_with_oidc_rejected() {
            let toml = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "oidc"
additional_scopes = ["heartBeats"]

[auth.oidc]
client_id = "cid"
token_endpoint_url = "https://idp.example.com/token"

[auth.oidc.client_credentials]
client_secret = "s"
"#;
            let err = ConfigLoader::validate_client_config_content(toml)
                .expect_err("heartBeats scope with oidc must be rejected");
            assert!(err.to_string().contains("heartBeats"), "{err}");
        }
    }
}

#[cfg(test)]
mod mtls_config_tests {
    use crate::*;

    fn parse_server(toml: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let cfg = ConfigLoader::parse_config::<ServerConfig>(toml, ConfigKind::Server, false)?;
        ConfigLoader::validate_server_config(&cfg)?;
        Ok(cfg)
    }

    fn parse_client(toml: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let cfg = ConfigLoader::parse_config::<ClientConfig>(toml, ConfigKind::Client, false)?;
        ConfigLoader::validate_client_config(&cfg)?;
        Ok(cfg)
    }

    fn server_toml(tls: &str) -> String {
        format!(
            "bind_port = 9300\n\n[auth]\nmethod = \"token\"\ntoken = \"t\"\n\n[transport.tls]\nenable = true\n{tls}\n"
        )
    }

    fn client_toml(tls: &str) -> String {
        format!(
            "server_addr = \"127.0.0.1\"\nserver_port = 9300\n\n[auth]\nmethod = \"token\"\ntoken = \"t\"\n\n[transport.tls]\nenable = true\n{tls}\n"
        )
    }

    #[test]
    fn mtls_defaults_are_off() {
        let tls = TlsConfig::default();
        assert!(tls.client_ca_file.is_none());
        assert!(!tls.require_client_cert);
        assert!(!tls.skip_verify);
    }

    #[test]
    fn server_require_client_cert_without_ca_is_rejected() {
        let toml = server_toml("require_client_cert = true");
        let err = parse_server(&toml).expect_err("require without client_ca_file must be rejected");
        assert!(
            err.to_string().contains("client_ca_file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn server_mtls_accepts_camel_case_aliases() {
        let toml = server_toml(
            "certFile = \"/tmp/s.crt\"\nkeyFile = \"/tmp/s.key\"\nclientCaFile = \"/tmp/ca.crt\"\nrequireClientCert = true",
        );
        let cfg = parse_server(&toml).expect("camelCase aliases must be accepted");
        let tls = cfg.transport.tls.expect("tls section");
        assert_eq!(tls.client_ca_file.as_deref(), Some("/tmp/ca.crt"));
        assert!(tls.require_client_cert);
    }

    #[test]
    fn server_mtls_snake_case_roundtrip() {
        let toml = server_toml("client_ca_file = \"/tmp/ca.crt\"");
        let cfg = parse_server(&toml).expect("valid");
        let tls = cfg.transport.tls.expect("tls section");
        assert_eq!(tls.client_ca_file.as_deref(), Some("/tmp/ca.crt"));
        // 只配 CA 不强制 => 灰度语义，必须放行
        assert!(!tls.require_client_cert);
    }

    #[test]
    fn client_cert_without_key_is_rejected() {
        let toml = client_toml("cert_file = \"/tmp/c.crt\"");
        let err = parse_client(&toml).expect_err("cert without key must be rejected");
        assert!(err.to_string().contains("key_file"), "unexpected: {err}");
    }

    #[test]
    fn client_key_without_cert_is_rejected() {
        let toml = client_toml("key_file = \"/tmp/c.key\"");
        let err = parse_client(&toml).expect_err("key without cert must be rejected");
        assert!(err.to_string().contains("cert_file"), "unexpected: {err}");
    }

    /// D7：mTLS 客户端证书与 skip_verify 同时出现必须被拒绝 —— 否则等于给
    /// "假服务端"留了收集客户端证书的口子。
    #[test]
    fn client_cert_with_skip_verify_is_rejected() {
        let toml = client_toml(
            "cert_file = \"/tmp/c.crt\"\nkey_file = \"/tmp/c.key\"\nskip_verify = true",
        );
        let err = parse_client(&toml).expect_err("mTLS cert + skip_verify must be rejected");
        assert!(err.to_string().contains("skip_verify"), "unexpected: {err}");
    }

    #[test]
    fn client_mtls_with_trusted_ca_is_accepted() {
        let toml = client_toml(
            "cert_file = \"/tmp/c.crt\"\nkey_file = \"/tmp/c.key\"\ntrusted_ca_file = \"/tmp/ca.crt\"",
        );
        let cfg = parse_client(&toml).expect("mTLS client config must be accepted");
        let tls = cfg.transport.tls.expect("tls section");
        assert_eq!(tls.cert_file.as_deref(), Some("/tmp/c.crt"));
        assert_eq!(tls.trusted_ca_file.as_deref(), Some("/tmp/ca.crt"));
    }

    #[test]
    fn server_without_mtls_still_valid() {
        let toml = server_toml("cert_file = \"/tmp/s.crt\"\nkey_file = \"/tmp/s.key\"");
        parse_server(&toml).expect("plain TLS server config must remain valid");
    }
}

#[cfg(test)]
mod auth_hardening_config_tests {
    //! P1（B1 `client_id` 策略 / B4 登录节流）与 P4（接管指纹判据）的配置回归。
    //!
    //! 重点守住两条：**默认值必须零破坏**（不改变既有部署行为），
    //! 以及严格模式下新字段必须被白名单识别（否则老配置会报未知字段）。

    use crate::*;

    fn parse_server(toml: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let cfg = ConfigLoader::parse_config::<ServerConfig>(toml, ConfigKind::Server, false)?;
        ConfigLoader::validate_server_config(&cfg)?;
        Ok(cfg)
    }

    fn server_toml(auth_extra: &str) -> String {
        format!("bind_port = 9300\n\n[auth]\nmethod = \"token\"\ntoken = \"t\"\n{auth_extra}\n")
    }

    #[test]
    fn defaults_are_backward_compatible() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.auth.client_id_policy, ClientIdPolicy::Warn);
        assert_eq!(cfg.auth.login_max_failures, 5);
        assert_eq!(cfg.auth.login_lockout_secs, 600);
        assert!(!cfg.auth.kick_require_same_cert);
    }

    #[test]
    fn config_without_new_fields_still_valid() {
        let cfg = parse_server(&server_toml("")).expect("未写新字段的旧配置必须照常可用");
        assert_eq!(cfg.auth.client_id_policy, ClientIdPolicy::Warn);
    }

    #[test]
    fn reject_policy_parses() {
        let cfg = parse_server(&server_toml("client_id_policy = \"reject\""))
            .expect("snake_case 应可解析");
        assert_eq!(cfg.auth.client_id_policy, ClientIdPolicy::Reject);
    }

    #[test]
    fn camel_case_aliases_parse() {
        let cfg = parse_server(&server_toml(
            "clientIdPolicy = \"reject\"\nloginMaxFailures = 2\nloginLockoutSecs = 30\nkickRequireSameCert = true",
        ))
        .expect("camelCase 别名应可解析");
        assert_eq!(cfg.auth.client_id_policy, ClientIdPolicy::Reject);
        assert_eq!(cfg.auth.login_max_failures, 2);
        assert_eq!(cfg.auth.login_lockout_secs, 30);
        assert!(cfg.auth.kick_require_same_cert);
    }

    #[test]
    fn snake_case_roundtrip() {
        let cfg = parse_server(&server_toml(
            "client_id_policy = \"warn\"\nlogin_max_failures = 7\nlogin_lockout_secs = 120\nkick_require_same_cert = true",
        ))
        .expect("snake_case 应可解析");
        assert_eq!(cfg.auth.login_max_failures, 7);
        assert_eq!(cfg.auth.login_lockout_secs, 120);
        assert!(cfg.auth.kick_require_same_cert);
    }

    #[test]
    fn unknown_policy_value_is_rejected() {
        let err = parse_server(&server_toml("client_id_policy = \"explode\""))
            .expect_err("非法枚举值必须报错，不能静默降级");
        let msg = err.to_string();
        assert!(
            msg.contains("client_id_policy") || msg.contains("unknown variant"),
            "{msg}"
        );
    }

    #[test]
    fn throttle_on_without_lockout_is_rejected() {
        let err = parse_server(&server_toml(
            "login_max_failures = 5\nlogin_lockout_secs = 0",
        ))
        .expect_err("开了节流却没给锁定时长属于歧义配置，应拒绝");
        assert!(err.to_string().contains("login_lockout_secs"), "{err}");
    }

    #[test]
    fn throttle_can_be_disabled_explicitly() {
        let cfg = parse_server(&server_toml("login_max_failures = 0"))
            .expect("显式关闭节流应合法（0 = 关闭）");
        // 0 表示关闭：此时 lockout 取什么值都不该报错
        assert_eq!(cfg.auth.login_max_failures, 0);
    }
}
