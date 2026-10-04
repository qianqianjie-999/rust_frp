//! 配置兼容层：对齐原版 fatedier/frp 的 camelCase 字段名 + 未知字段告警。
//!
//! # 背景
//!
//! 原版 frp（v0.71+ TOML 配置）字段名为 camelCase（如 `serverAddr`、`localIP`），
//! 本项目的 canonical 字段名为 snake_case（如 `server_addr`、`local_ip`）。
//! 通过 serde `alias` 让两种拼写都能解析（canonical 优先，alias 兼容），
//! 使原版配置文件可直接复用。
//!
//! # 未知字段
//!
//! 原版配置包含本项目暂不支持的字段（如 `log.to`、`loginFailExit`、
//! `transport.heartbeatInterval`）。若启用 `deny_unknown_fields` 会直接拒绝
//! 整份配置，迁移成本反而更高；因此采取「解析成功 + 逐字段 WARN」策略：
//! 配置能跑，但用户能明确知道哪些字段未生效。

use serde_json::Value;

/// 配置种类（决定顶层键集）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigKind {
    Server,
    Client,
}

/// 各 section 的已知键（canonical snake_case + 原版 camelCase alias）
mod fields {
    pub const SERVER_ROOT: &[&str] = &[
        "bind_addr",
        "bindAddr",
        "bind_port",
        "bindPort",
        "kcp_bind_port",
        "kcpBindPort",
        "quic_bind_port",
        "quicBindPort",
        "vhost_http_port",
        "vhostHTTPPort",
        "vhost_https_port",
        "vhostHTTPSPort",
        "tcpmux_http_connect_port",
        "tcpmuxHTTPConnectPort",
        "work_conn_port",
        "workConnPort",
        "web_server",
        "webServer",
        "auth",
        "transport",
        "allow_ports",
        "allowPorts",
        "max_ports_per_user",
        "maxPortsPerUser",
        "custom_404_page",
        "custom404Page",
        "includes",
        "proxies",
        "http_plugins",
        "httpPlugins",
    ];

    pub const CLIENT_ROOT: &[&str] = &[
        "server_addr",
        "serverAddr",
        "server_port",
        "serverPort",
        "work_conn_port",
        "workConnPort",
        "user",
        "client_id",
        "clientID",
        "web_server",
        "webServer",
        "auth",
        "transport",
        "proxies",
        "visitors",
        "includes",
    ];

    pub const WEB_SERVER: &[&str] = &[
        "addr",
        "port",
        "user",
        "password",
        "expose_metrics",
        "exposeMetrics",
    ];

    pub const AUTH: &[&str] = &["method", "token", "oidc"];

    pub const OIDC: &[&str] = &[
        "issuer",
        "audience",
        "client_id",
        "clientID",
        "client_secret",
        "clientSecret",
        "token_endpoint_url",
        "tokenEndpointURL",
        "scope",
        "additional_endpoint_params",
        "additionalEndpointParams",
        "trusted_ca_file",
        "trustedCaFile",
        "insecure_skip_verify",
        "insecureSkipVerify",
        "skip_expiry_check",
        "skipExpiryCheck",
        "skip_issuer_check",
        "skipIssuerCheck",
    ];

    pub const TRANSPORT: &[&str] = &[
        "protocol",
        "tls",
        "tcp_mux",
        "tcpMux",
        "tls_only",
        "tlsOnly",
        "pool_count",
        "poolCount",
        "bandwidth_limit",
        "bandwidthLimit",
        "use_encryption",
        "useEncryption",
        "use_compression",
        "useCompression",
        "quic",
        "bandwidth_limit_mode",
        "bandwidthLimitMode",
        "proxy_protocol_version",
        "proxyProtocolVersion",
    ];

    pub const TLS: &[&str] = &[
        "enable",
        "cert_file",
        "certFile",
        "key_file",
        "keyFile",
        "trusted_ca_file",
        "trustedCaFile",
        "skip_verify",
        "skipVerify",
        "force",
    ];

    pub const QUIC: &[&str] = &[
        "max_idle_timeout",
        "maxIdleTimeout",
        "max_incoming_streams",
        "maxIncomingStreams",
        "keepalive_period",
        "keepalivePeriod",
    ];

    pub const PROXY: &[&str] = &[
        "name",
        "type",
        "local_ip",
        "localIP",
        "local_port",
        "localPort",
        "remote_port",
        "remotePort",
        "custom_domains",
        "customDomains",
        "subdomain",
        "subDomain",
        "locations",
        "host_header_rewrite",
        "hostHeaderRewrite",
        "http_user",
        "httpUser",
        "http_password",
        "httpPassword",
        "health_check",
        "healthCheck",
        "bandwidth_limit",
        "bandwidthLimit",
        "secret_key",
        "secretKey",
        "transport",
        "plugin",
        "proxy_protocol",
        "proxyProtocol",
        "group",
        "group_key",
        "groupKey",
        "use_encryption",
        "useEncryption",
        "use_compression",
        "useCompression",
        "multiplexer",
        "route_by_http_user",
        "routeByHTTPUser",
        "allow_users",
        "allowUsers",
    ];

    pub const VISITOR: &[&str] = &[
        "name",
        "type",
        "server_name",
        "serverName",
        "secret_key",
        "secretKey",
        "bind_addr",
        "bindAddr",
        "bind_port",
        "bindPort",
        "transport",
        "use_encryption",
        "useEncryption",
        "use_compression",
        "useCompression",
    ];

    pub const HEALTH_CHECK: &[&str] = &[
        "type",
        "timeout_seconds",
        "timeoutSeconds",
        "max_failed",
        "maxFailed",
        "interval_seconds",
        "intervalSeconds",
        "path",
    ];

    pub const PLUGIN: &[&str] = &[
        "type",
        "unix_path",
        "unixPath",
        "local_path",
        "localPath",
        "strip_prefix",
        "stripPrefix",
        "http_user",
        "httpUser",
        "http_password",
        "httpPassword",
        "local_addr",
        "localAddr",
        "crt_path",
        "crtPath",
        "key_path",
        "keyPath",
    ];

    pub const PORT_RANGE: &[&str] = &["start", "end", "single"];

    pub const HTTP_PLUGIN: &[&str] = &["name", "addr", "path", "ops", "tls_verify", "tlsVerify"];
}

fn section_fields(section: &str) -> &'static [&'static str] {
    match section {
        "server_root" => fields::SERVER_ROOT,
        "client_root" => fields::CLIENT_ROOT,
        "web_server" => fields::WEB_SERVER,
        "auth" => fields::AUTH,
        "oidc" => fields::OIDC,
        "transport" => fields::TRANSPORT,
        "tls" => fields::TLS,
        "quic" => fields::QUIC,
        "proxy" => fields::PROXY,
        "visitor" => fields::VISITOR,
        "health_check" => fields::HEALTH_CHECK,
        "plugin" => fields::PLUGIN,
        "port_range" => fields::PORT_RANGE,
        "http_plugin" => fields::HTTP_PLUGIN,
        _ => &[],
    }
}

/// 返回子表 (key, child_section)。数组型子表（proxies/visitors 等）同样返回，
/// 由调用方按 Object/Array 分别处理。
fn child_section(section: &str, key: &str) -> Option<&'static str> {
    match section {
        "server_root" | "client_root" => match key {
            "web_server" | "webServer" => Some("web_server"),
            "auth" => Some("auth"),
            "transport" => Some("transport"),
            "proxies" => Some("proxy"),
            "visitors" => Some("visitor"),
            "allow_ports" | "allowPorts" => Some("port_range"),
            "http_plugins" | "httpPlugins" => Some("http_plugin"),
            _ => None,
        },
        "auth" => (key == "oidc").then_some("oidc"),
        "transport" => match key {
            "tls" => Some("tls"),
            "quic" => Some("quic"),
            _ => None,
        },
        "proxy" => match key {
            "transport" => Some("transport"),
            "plugin" => Some("plugin"),
            "health_check" | "healthCheck" => Some("health_check"),
            _ => None,
        },
        "visitor" => (key == "transport").then_some("transport"),
        _ => None,
    }
}

/// 收集配置中无法识别的字段路径（如 `log`、`proxies[0].metadatas`）。
pub(crate) fn collect_unknown_fields(kind: ConfigKind, root: &Value) -> Vec<String> {
    let mut out = Vec::new();
    match kind {
        ConfigKind::Server => check_table("server_root", "", root, &mut out),
        ConfigKind::Client => check_table("client_root", "", root, &mut out),
    }
    out
}

fn check_table(section: &str, path: &str, value: &Value, out: &mut Vec<String>) {
    let Some(obj) = value.as_object() else {
        return;
    };
    let known = section_fields(section);
    for (key, val) in obj {
        if !known.contains(&key.as_str()) {
            out.push(format!("{path}{key}"));
            continue;
        }
        let Some(child) = child_section(section, key) else {
            continue;
        };
        match val {
            Value::Object(_) => check_table(child, &format!("{path}{key}."), val, out),
            Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    if !item.is_object() {
                        continue;
                    }
                    check_table(child, &format!("{path}{key}[{i}]."), item, out);
                }
            }
            _ => {}
        }
    }
}

/// 解析成功后对未知字段打印 WARN（最多 10 条，避免刷屏）。
pub(crate) fn warn_unknown_fields(kind: ConfigKind, root: &Value) {
    let unknown = collect_unknown_fields(kind, root);
    if unknown.is_empty() {
        return;
    }
    log::warn!(
        "Config contains {} unrecognized field(s) that will be ignored:",
        unknown.len()
    );
    for field in unknown.iter().take(10) {
        log::warn!("  - `{field}` is not supported by this implementation (ignored)");
    }
    if unknown.len() > 10 {
        log::warn!("  - ... and {} more", unknown.len() - 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_server_root_known_fields() {
        let root = json!({
            "bindPort": 7000,
            "vhostHTTPPort": 8080,
            "webServer": { "port": 7500, "user": "admin", "password": "x", "exposeMetrics": true },
            "auth": { "method": "token", "token": "abc" },
            "transport": { "tls": { "force": true } },
            "allowPorts": [{ "start": 10000, "end": 20000 }]
        });
        assert!(collect_unknown_fields(ConfigKind::Server, &root).is_empty());
    }

    #[test]
    fn test_client_unknown_fields_reported() {
        let root = json!({
            "serverAddr": "1.2.3.4",
            "serverPort": 7000,
            "loginFailExit": true,
            "log": { "to": "./frpc.log", "level": "info" },
            "proxies": [
                { "name": "ssh", "type": "tcp", "localIP": "127.0.0.1", "localPort": 22, "remotePort": 6022, "metadatas": {} }
            ]
        });
        let unknown = collect_unknown_fields(ConfigKind::Client, &root);
        assert!(
            unknown.contains(&"loginFailExit".to_string()),
            "got {unknown:?}"
        );
        assert!(unknown.contains(&"log".to_string()), "got {unknown:?}");
        assert!(
            unknown.contains(&"proxies[0].metadatas".to_string()),
            "got {unknown:?}"
        );
    }

    /// 回归：`transport.quic.*`（camelCase）必须属于客户端已知键，
    /// 否则 `protocol = "quic"` 的配置会被整体误报为未知字段。
    #[test]
    fn test_transport_quic_keys_are_known() {
        let root = json!({
            "serverAddr": "1.2.3.4",
            "serverPort": 7000,
            "transport": {
                "protocol": "quic",
                "quic": {
                    "maxIdleTimeout": 30,
                    "maxIncomingStreams": 100000,
                    "keepalivePeriod": 0
                }
            }
        });
        assert!(collect_unknown_fields(ConfigKind::Client, &root).is_empty());
    }

    /// 回归：`http_plugins`/`httpPlugins` 必须属于服务端已知键，
    /// 否则上一轮新增的服务端插件配置会被整体误报为未知字段（含其子键）。
    #[test]
    fn test_http_plugins_and_oidc_keys_are_known() {
        let root = json!({
            "bindPort": 7000,
            "httpPlugins": [
                { "name": "p", "addr": "http://127.0.0.1:9000", "path": "/cb",
                  "ops": ["Login"], "tlsVerify": true }
            ],
            "http_plugins": [],
            "auth": {
                "method": "oidc",
                "oidc": {
                    "issuer": "https://idp",
                    "audience": "frp",
                    "clientID": "c",
                    "clientSecret": "s",
                    "tokenEndpointURL": "https://idp/token",
                    "scope": "openid",
                    "additionalEndpointParams": { "resource": "r" },
                    "trustedCaFile": "/etc/ca.pem",
                    "insecureSkipVerify": false,
                    "skipExpiryCheck": false,
                    "skipIssuerCheck": false
                }
            }
        });
        let unknown = collect_unknown_fields(ConfigKind::Server, &root);
        assert!(unknown.is_empty(), "unexpected unknown fields: {unknown:?}");
    }

    #[test]
    fn test_proxy_subsections() {
        let root = json!({
            "proxies": [{
                "name": "web",
                "type": "http",
                "localIP": "127.0.0.1",
                "localPort": 80,
                "customDomains": ["a.com"],
                "transport": { "useEncryption": true, "useCompression": false },
                "healthCheck": { "type": "http", "path": "/health", "timeoutSeconds": 3 },
                "plugin": { "type": "static_file", "localPath": "/var/www" }
            }]
        });
        assert!(collect_unknown_fields(ConfigKind::Client, &root).is_empty());
    }

    #[test]
    fn test_tcpmux_sudp_and_compression_keys_are_known() {
        // tcpmux/sudp 专属字段 + 代理/访客顶层的 useCompression 不应产生未知字段告警
        let root = json!({
            "proxies": [
                {
                    "name": "mux",
                    "type": "tcpmux",
                    "multiplexer": "httpconnect",
                    "routeByHTTPUser": "alice",
                    "httpUser": "alice",
                    "httpPassword": "pw",
                    "customDomains": ["a.com"],
                    "useCompression": true,
                    "useEncryption": false
                },
                {
                    "name": "udp-p2p",
                    "type": "sudp",
                    "localIP": "127.0.0.1",
                    "localPort": 53,
                    "secretKey": "s3cret",
                    "allowUsers": ["alice"]
                }
            ],
            "visitors": [
                {
                    "name": "visit-udp",
                    "type": "sudp",
                    "serverName": "udp-p2p",
                    "secretKey": "s3cret",
                    "bindAddr": "127.0.0.1",
                    "bindPort": 5353,
                    "useCompression": true
                }
            ]
        });
        let unknown = collect_unknown_fields(ConfigKind::Client, &root);
        assert!(unknown.is_empty(), "unexpected unknown fields: {unknown:?}");
    }

    #[test]
    fn test_visitor_and_transport_tls() {
        let root = json!({
            "visitors": [{
                "name": "v1",
                "type": "stcp",
                "serverName": "ssh",
                "secretKey": "k",
                "bindAddr": "0.0.0.0",
                "bindPort": 9000,
                "transport": { "tls": { "trustedCaFile": "/ca.pem" } }
            }]
        });
        assert!(collect_unknown_fields(ConfigKind::Client, &root).is_empty());
    }
}
