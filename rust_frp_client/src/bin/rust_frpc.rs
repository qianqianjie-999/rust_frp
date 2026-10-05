//! `rust_frpc` 命令行入口
//!
//! 子命令对齐原版 frp 0.71 `cmd/frpc/sub`：
//!
//! | 形式 | 语义 |
//! |------|------|
//! | `frpc [-c path]` | 按配置文件运行 |
//! | `frpc --config_dir <dir>` | 目录内每个配置文件各起一个客户端实例（多实例） |
//! | `frpc verify [-c path]` | 校验配置文件 |
//! | `frpc reload [-c path]` | 请求运行中的 frpc 热重载（管理端口 `POST /reload`） |
//! | `frpc status [-c path]` | 查询运行中的 frpc 代理状态（`GET /status`） |
//! | `frpc stop [-c path]` | 停止运行中的 frpc（`POST /stop`） |
//! | `frpc nathole discover` | 经 STUN 探测 NAT 类型（对齐 `nathole discover`） |
//! | `frpc <type> [flags]` | 单代理快速启动（tcp/udp/http/https/tcpmux/stcp/sudp/xtcp/websocket） |
//! | `frpc <type> visitor [flags]` | 单访问者快速启动（stcp/sudp/xtcp） |
//!
//! 通用旗标：`-c/--config`、`--config_dir`、`-v/--version`、`--api-timeout <secs>`。
//! 快速启动旗标：`-s/--server_addr`、`-p/--server_port`、`-t/--token`、`-u/--user`、
//! `-n/--name`、`--local_ip`、`--local_port`、`--remote_port`、`--custom_domains`、
//! `--subdomain`、`--secret_key`、`--allow_users`、`--group`、`--group_key`、
//! `--use_encryption`、`--use_compression`、`--plugin`；访问者另有
//! `--server_name`、`--bind_addr`、`--bind_port`。
//! 长旗标同时接受 snake_case 与原版 camelCase 拼写。

use rust_frp_client::{admin_client::admin_http_request, Client};
use rust_frp_config::{ClientConfig, ConfigLoader, PluginConfig, ProxyConfig, VisitorConfig};
use std::process::exit;
use std::time::Duration;
use tracing::{error, info};

/// 支持的代理类型（`frpc <type>` 快速启动）
const PROXY_TYPES: &[&str] = &[
    "tcp",
    "udp",
    "http",
    "https",
    "tcpmux",
    "stcp",
    "sudp",
    "xtcp",
    "websocket",
];

/// 支持 `visitor` 子子命令的代理类型
const VISITOR_TYPES: &[&str] = &["stcp", "sudp", "xtcp"];

/// 默认管理 API 超时（与原版 `adminAPITimeout` 一致）
const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(30);

/// frpc 子命令
#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    /// 默认：前台运行客户端
    Run,
    /// 校验配置文件（语法 + 校验规则），不连接服务端
    Verify,
    /// 请求运行中的 frpc 热重载配置（走管理端口 POST /reload）
    Reload,
    /// 查询运行中的 frpc 代理状态（走管理端口 GET /status）
    Status,
    /// 停止运行中的 frpc（走管理端口 POST /stop）
    Stop,
    /// 经 STUN 探测 NAT 类型（`frpc nathole discover`）
    NatholeDiscover,
    /// 单代理快速启动（`frpc <type> [flags]`）
    Proxy(String),
    /// 单访问者快速启动（`frpc <type> visitor [flags]`）
    Visitor(String),
}

/// 快速启动模式下的旗标集合（配置文件模式下留空）
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct QuickOpts {
    server_addr: Option<String>,
    server_port: Option<u16>,
    token: Option<String>,
    user: Option<String>,
    name: Option<String>,
    local_ip: Option<String>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    custom_domains: Vec<String>,
    subdomain: Option<String>,
    secret_key: Option<String>,
    allow_users: Vec<String>,
    group: Option<String>,
    group_key: Option<String>,
    use_encryption: bool,
    use_compression: bool,
    plugin: Option<String>,
    // ---- 访问者 ----
    server_name: Option<String>,
    bind_addr: Option<String>,
    bind_port: Option<u16>,
    // ---- nathole discover ----
    stun_server: Option<String>,
    stun_local_addr: Option<String>,
    /// 快速启动显式给了 `--local_ip` 等代理旗标（用于校验提示）
    has_proxy_flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    command: Command,
    config_path: Option<String>,
    config_dir: Option<String>,
    version: bool,
    api_timeout: Duration,
    /// 对齐原版 `--strict_config`（默认 true）：未知字段直接报错
    strict_config: bool,
    opts: QuickOpts,
}

const USAGE: &str =
    "usage: frpc [verify|reload|status|stop|nathole discover|<proxy_type> [visitor]] \
                     [-c config_path] [--config_dir dir] [-v] [--api-timeout secs]";

/// 解析 `--key=value` / `--key value` 形式的旗标名与内联值
fn split_flag(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (arg, None),
    }
}

/// 取旗标值：优先内联 `--key=value`，否则消费下一个参数
fn take_flag_value(
    args: &[String],
    i: &mut usize,
    inline: Option<&str>,
    name: &str,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v.to_string());
    }
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

/// 解析 `frpc` 命令行参数。
///
/// 子命令只允许出现在第一个位置（`<type> visitor` 除外）；
/// 非首位出现子命令关键字会被视为未知参数而报错。
fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut command = Command::Run;
    let mut start = 0usize;

    if let Some(first) = args.first().map(String::as_str) {
        match first {
            "verify" => {
                command = Command::Verify;
                start = 1;
            }
            "reload" => {
                command = Command::Reload;
                start = 1;
            }
            "status" => {
                command = Command::Status;
                start = 1;
            }
            "stop" => {
                command = Command::Stop;
                start = 1;
            }
            "nathole" => {
                if args.get(1).map(String::as_str) != Some("discover") {
                    return Err(format!(
                        "unknown nathole subcommand: {}\nusage: frpc nathole discover \
                         [--nat_hole_stun_server <addr>] [-l <local_addr>]",
                        args.get(1).map(String::as_str).unwrap_or("<missing>")
                    ));
                }
                command = Command::NatholeDiscover;
                start = 2;
            }
            t if PROXY_TYPES.contains(&t) => {
                command = Command::Proxy(t.to_string());
                start = 1;
                if VISITOR_TYPES.contains(&t) && args.get(1).map(String::as_str) == Some("visitor")
                {
                    command = Command::Visitor(t.to_string());
                    start = 2;
                }
            }
            _ => {}
        }
    }

    let mut config_path: Option<String> = None;
    let mut config_dir: Option<String> = None;
    let mut version = false;
    let mut api_timeout = DEFAULT_API_TIMEOUT;
    let mut strict_config = true;
    let mut opts = QuickOpts::default();

    let mut i = start;
    while i < args.len() {
        let (key, inline) = split_flag(&args[i]);
        // `take` 时消费下一个参数（`--key value` 形式）
        macro_rules! take {
            () => {
                take_flag_value(&args, &mut i, inline, key)?
            };
        }

        match key {
            "-c" | "--config" => config_path = Some(take!()),
            "--config_dir" | "--config-dir" => config_dir = Some(take!()),
            "-v" | "--version" => version = true,
            "--api-timeout" => {
                api_timeout = parse_duration(&take!())?;
            }
            // 对齐原版 --strict_config（默认 true）：仅接受显式 bool 内联值
            "--strict_config" | "--strict-config" => {
                strict_config = match inline {
                    Some(v) => matches!(v, "true" | "1" | "TRUE" | "True"),
                    None => true,
                };
            }
            "-s" | "--server_addr" | "--serverAddr" => {
                opts.server_addr = Some(take!());
                opts.has_proxy_flag = true;
            }
            "-p" | "--server_port" | "--serverPort" => {
                opts.server_port = Some(parse_u16(&take!(), key)?);
            }
            "-t" | "--token" => opts.token = Some(take!()),
            "-u" | "--user" => opts.user = Some(take!()),
            "-n" | "--name" => {
                opts.name = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--local_ip" | "--localIP" => {
                opts.local_ip = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--local_port" | "--localPort" => {
                opts.local_port = Some(parse_u16(&take!(), key)?);
                opts.has_proxy_flag = true;
            }
            "--remote_port" | "--remotePort" => {
                opts.remote_port = Some(parse_u16(&take!(), key)?);
                opts.has_proxy_flag = true;
            }
            "--custom_domains" | "--customDomains" => {
                opts.custom_domains.extend(split_list(&take!()));
                opts.has_proxy_flag = true;
            }
            "--subdomain" | "--subDomain" => {
                opts.subdomain = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--secret_key" | "--secretKey" => {
                opts.secret_key = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--allow_users" | "--allowUsers" => {
                opts.allow_users.extend(split_list(&take!()));
                opts.has_proxy_flag = true;
            }
            "--group" => {
                opts.group = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--group_key" | "--groupKey" => {
                opts.group_key = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--use_encryption" | "--useEncryption" => {
                opts.use_encryption = true;
                opts.has_proxy_flag = true;
            }
            "--use_compression" | "--useCompression" => {
                opts.use_compression = true;
                opts.has_proxy_flag = true;
            }
            "--plugin" => {
                opts.plugin = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--server_name" | "--serverName" => {
                opts.server_name = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--bind_addr" | "--bindAddr" => {
                opts.bind_addr = Some(take!());
                opts.has_proxy_flag = true;
            }
            "--bind_port" | "--bindPort" => {
                opts.bind_port = Some(parse_u16(&take!(), key)?);
                opts.has_proxy_flag = true;
            }
            "--nat_hole_stun_server" | "--natHoleStunServer" => {
                opts.stun_server = Some(take!());
            }
            "-l" | "--nat_hole_local_addr" | "--natHoleLocalAddr" => {
                opts.stun_local_addr = Some(take!());
            }
            other => {
                return Err(format!("unknown argument: {other}\n{USAGE}"));
            }
        }
        i += 1;
    }

    // 配置文件模式下不接受代理旗标，避免「以为生效了其实被忽略」
    if matches!(command, Command::Run | Command::Verify)
        && opts.has_proxy_flag
        && config_path.is_some()
    {
        // 仅提示：`-c` 与代理旗标混用属误用
        return Err(format!(
            "proxy flags can not be used together with -c/--config\n{USAGE}"
        ));
    }

    Ok(CliArgs {
        command,
        config_path,
        config_dir,
        version,
        api_timeout,
        strict_config,
        opts,
    })
}

/// `1` / `30s` / `500ms` / `2m` → Duration
fn parse_duration(raw: &str) -> Result<Duration, String> {
    let s = raw.trim();
    let (num, unit) = if let Some(v) = s.strip_suffix("ms") {
        (v, "ms")
    } else if let Some(v) = s.strip_suffix('s') {
        (v, "s")
    } else if let Some(v) = s.strip_suffix('m') {
        (v, "m")
    } else {
        (s, "s")
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration: {raw}"))?;
    if n < 0.0 || !n.is_finite() {
        return Err(format!("invalid duration: {raw}"));
    }
    Ok(match unit {
        "ms" => Duration::from_millis(n as u64),
        "m" => Duration::from_secs_f64(n * 60.0),
        _ => Duration::from_secs_f64(n),
    })
}

fn parse_u16(raw: &str, flag: &str) -> Result<u16, String> {
    raw.trim()
        .parse::<u16>()
        .map_err(|_| format!("{flag} expects a number in 0..65535, got: {raw}"))
}

/// 逗号分隔列表（去空白、丢空项），支持重复旗标累加
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn non_empty(v: Vec<String>) -> Option<Vec<String>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn default_config_path(config_path: &Option<String>) -> String {
    config_path
        .clone()
        .unwrap_or_else(|| "frpc.toml".to_string())
}

/// 加载配置；失败打印错误并以退出码 1 结束
fn load_config_or_exit(config_path: &Option<String>, strict: bool) -> ClientConfig {
    let path = default_config_path(config_path);
    match ConfigLoader::load_client_config_strict(&path, strict) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("frpc: load config from {path} failed: {e}");
            exit(1);
        }
    }
}

/// `frpc verify`：校验配置文件后按结果设置退出码
fn run_verify(config_path: &Option<String>, strict: bool) {
    let path = default_config_path(config_path);
    match ConfigLoader::load_client_config_strict(&path, strict) {
        Ok(config) => {
            println!(
                "syntax check pass: {} proxies, {} visitors",
                config.proxies.len(),
                config.visitors.len()
            );
        }
        Err(e) => {
            eprintln!("frpc: verify config in {path} failed: {e}");
            exit(1);
        }
    }
}

/// `frpc reload` / `status` / `stop`：请求管理端口并打印响应
async fn run_admin(
    config_path: &Option<String>,
    method: &str,
    path: &str,
    timeout: Duration,
    strict: bool,
) {
    let config = load_config_or_exit(config_path, strict);
    let ws = &config.web_server;
    if ws.port == 0 {
        eprintln!(
            "frpc: admin API is disabled (web_server.port = 0); \
             enable it in frpc.toml [webServer] section first"
        );
        exit(1);
    }
    // user/password 成对配置时附带 Basic 认证
    let auth = match (ws.user.as_deref(), ws.password.as_deref()) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
        _ => None,
    };

    let request = admin_http_request(&ws.addr, ws.port, method, path, auth);
    let result = match tokio::time::timeout(timeout, request).await {
        Ok(r) => r,
        Err(_) => {
            eprintln!(
                "frpc: request {method} {path} timed out after {:?} (--api-timeout)",
                timeout
            );
            exit(1);
        }
    };

    match result {
        Ok((status, body)) => {
            if status == 200 {
                // 尝试格式化 JSON 便于阅读；解析失败则原样输出
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or(body)),
                    Err(_) => println!("{body}"),
                }
            } else {
                eprintln!("frpc: admin API returned {status}: {body}");
                exit(1);
            }
        }
        Err(e) => {
            eprintln!(
                "frpc: request {} {} failed: {e} (is frpc running with webServer enabled?)",
                method, path
            );
            exit(1);
        }
    }
}

/// `frpc nathole discover`：STUN 采样 + NAT 行为分类
///
/// 对同一 UDP socket 依次向各 STUN 服务器探测公网映射：
/// 映射完全一致 → `EasyNAT`；IP 或端口变化 → `HardNAT`。
/// 与「本机出口 IP」相同的映射会标记 `PublicNetwork`。
async fn run_nathole_discover(opts: &QuickOpts) {
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    // 1. STUN 服务器：显式旗标优先，否则内置公共服务器
    let servers: Vec<std::net::SocketAddr> = match opts.stun_server.as_deref() {
        Some(s) if !s.is_empty() => match tokio::net::lookup_host(s).await {
            Ok(iter) => iter.collect(),
            Err(e) => {
                eprintln!("frpc: resolve STUN server {s} failed: {e}");
                exit(1);
            }
        },
        _ => rust_frp_net::default_stun_socket_addrs().await,
    };
    if servers.is_empty() {
        eprintln!(
            "frpc: no STUN server available; set --nat_hole_stun_server <host:port> \
             (built-in servers need DNS)"
        );
        exit(1);
    }

    // 2. 探测 socket（NAT 映射一致性的关键：所有探测复用同一 socket）
    let bind = opts
        .stun_local_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:0".to_string());
    let socket = match UdpSocket::bind(&bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("frpc: bind local address {bind} failed: {e}");
            exit(1);
        }
    };
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.clone());

    // 3. 逐服务器采样；采样数不足 2 时补采样首个服务器
    let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
    for server in &servers {
        match rust_frp_net::discover_from_server(Arc::clone(&socket), *server).await {
            Ok(a) => addrs.push(a),
            Err(e) => eprintln!("frpc: STUN server {server} probe failed: {e}"),
        }
    }
    while addrs.len() < 2 {
        let Some(first) = servers.first().copied() else {
            break;
        };
        match rust_frp_net::discover_from_server(Arc::clone(&socket), first).await {
            Ok(a) => addrs.push(a),
            Err(_) => break,
        }
    }
    if addrs.len() < 2 {
        eprintln!("frpc: discover error: can not get enough addresses, need 2, got: {addrs:?}");
        exit(1);
    }

    // 4. 本机出口 IP（判定 PublicNetwork）
    let local_ip = rust_frp_net::local_outbound_ip(servers[0]).await;

    // 5. 分类并输出
    let feature = match rust_frp_net::classify_nat_feature(&addrs, local_ip) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("frpc: classify nat feature error: {e}");
            exit(1);
        }
    };
    let addrs_str: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
    println!(
        "STUN server: {}",
        opts.stun_server
            .clone()
            .unwrap_or_else(|| { rust_frp_net::stun::DEFAULT_STUN_SERVERS.join(",") })
    );
    println!("Your NAT type is: {}", feature.nat_type);
    println!("Behavior is: {}", feature.behavior);
    println!("External address is: {:?}", addrs_str);
    println!("Local address is: {local_addr}");
    println!(
        "Public Network: {}",
        match local_ip {
            Some(ip) => format!("{} ({})", feature.public_network, ip),
            None => feature.public_network.to_string(),
        }
    );
}

/// 由快速启动旗标构造单代理 / 单访问者配置并运行客户端
async fn run_quick(command: &Command, opts: &QuickOpts) -> Result<(), String> {
    let mut cfg = ClientConfig::default();
    if let Some(v) = &opts.server_addr {
        cfg.server_addr = v.clone();
    }
    if let Some(v) = opts.server_port {
        cfg.server_port = v;
    }
    if let Some(v) = &opts.token {
        cfg.auth.method = "token".to_string();
        cfg.auth.token = Some(v.clone());
    }
    if let Some(v) = &opts.user {
        cfg.user = Some(v.clone());
    }

    match command {
        Command::Proxy(t) => {
            let has_plugin = opts.plugin.is_some();
            if !has_plugin && opts.local_port.unwrap_or(0) == 0 {
                return Err(format!(
                    "{t} proxy requires --local_port (or --plugin) in quick-run mode"
                ));
            }
            let proxy = ProxyConfig {
                name: opts.name.clone().unwrap_or_else(|| t.clone()),
                r#type: t.clone(),
                local_ip: opts
                    .local_ip
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                local_port: opts.local_port.unwrap_or(0),
                remote_port: opts.remote_port,
                custom_domains: non_empty(opts.custom_domains.clone()),
                subdomain: opts.subdomain.clone(),
                secret_key: opts.secret_key.clone(),
                allow_users: non_empty(opts.allow_users.clone()),
                group: opts.group.clone(),
                group_key: opts.group_key.clone(),
                use_encryption: opts.use_encryption,
                use_compression: opts.use_compression,
                plugin: opts.plugin.as_ref().map(|ty| PluginConfig {
                    r#type: ty.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            info!(
                "Quick-run {} proxy: name={} local={}:{} remote={:?}",
                proxy.r#type, proxy.name, proxy.local_ip, proxy.local_port, proxy.remote_port
            );
            cfg.proxies.push(proxy);
        }
        Command::Visitor(t) => {
            let server_name = opts.server_name.clone().unwrap_or_default();
            if server_name.is_empty() {
                return Err(format!(
                    "{t} visitor requires --server_name (the proxy name to visit)"
                ));
            }
            if opts.bind_port.unwrap_or(0) == 0 {
                return Err(format!("{t} visitor requires --bind_port"));
            }
            let visitor = VisitorConfig {
                name: opts.name.clone().unwrap_or_else(|| format!("{t}-visitor")),
                r#type: t.clone(),
                server_name,
                secret_key: opts.secret_key.clone(),
                bind_addr: opts
                    .bind_addr
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1".to_string()),
                bind_port: opts.bind_port.unwrap_or(0),
                use_encryption: opts.use_encryption,
                use_compression: opts.use_compression,
                ..Default::default()
            };
            info!(
                "Quick-run {} visitor: name={} server_name={} bind={}:{}",
                visitor.r#type,
                visitor.name,
                visitor.server_name,
                visitor.bind_addr,
                visitor.bind_port
            );
            cfg.visitors.push(visitor);
        }
        _ => return Err("internal error: run_quick called with non quick-run command".to_string()),
    }

    // 无配置文件：不启动文件监听（config_path = None）
    let mut client = Client::new(cfg, None).map_err(|e| e.to_string())?;
    client.start().await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("frpc: {e}");
            exit(2);
        }
    };

    if cli.version {
        println!("rust_frpc {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    match cli.command.clone() {
        Command::Verify => run_verify(&cli.config_path, cli.strict_config),
        Command::Reload => {
            run_admin(
                &cli.config_path,
                "POST",
                "/reload",
                cli.api_timeout,
                cli.strict_config,
            )
            .await;
        }
        Command::Status => {
            run_admin(
                &cli.config_path,
                "GET",
                "/status",
                cli.api_timeout,
                cli.strict_config,
            )
            .await;
        }
        Command::Stop => {
            run_admin(
                &cli.config_path,
                "POST",
                "/stop",
                cli.api_timeout,
                cli.strict_config,
            )
            .await;
        }
        Command::NatholeDiscover => run_nathole_discover(&cli.opts).await,
        Command::Proxy(_) | Command::Visitor(_) => {
            if let Err(e) = run_quick(&cli.command, &cli.opts).await {
                error!("{e}");
                exit(1);
            }
        }
        Command::Run => {
            if let Some(dir) = cli.config_dir.clone() {
                run_multiple_clients(&dir, cli.strict_config).await;
            } else {
                run_client(&cli.config_path, cli.strict_config).await;
            }
        }
    }
}

/// `--config_dir <dir>`：目录内每个配置文件各起一个客户端实例（多实例模式）
///
/// 对齐原版 `runMultipleClients`：目录下所有**文件**各起一个 frpc，
/// 任一实例失败只打印错误，不影响其他实例。
async fn run_multiple_clients(dir: &str, strict: bool) {
    let mut paths: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(e) => {
            eprintln!("frpc: read config dir {dir} failed: {e}");
            exit(1);
        }
    };
    paths.sort();
    if paths.is_empty() {
        eprintln!("frpc: no config file found in directory {dir}");
        exit(1);
    }

    info!(
        "Starting {} frpc instance(s) from config dir {}",
        paths.len(),
        dir
    );

    let mut handles = Vec::with_capacity(paths.len());
    for path in paths {
        let path_str = path.to_string_lossy().to_string();
        let task_path = path_str.clone();
        handles.push(tokio::spawn(async move {
            info!("[{}] starting frpc service", task_path);
            let result = run_client_once(&Some(task_path.clone()), strict).await;
            if let Err(e) = result {
                error!("[{}] frpc service stopped with error: {e}", task_path);
            } else {
                info!("[{}] frpc service stopped", task_path);
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// 默认运行模式：启动客户端主循环（失败即退出进程）
async fn run_client(config_path: &Option<String>, strict: bool) {
    if let Err(e) = run_client_once(config_path, strict).await {
        error!("Client error: {e}");
        exit(1);
    }
    info!("Client stopped normally");
}

/// 运行一个客户端实例，返回错误而不直接退出（供多实例模式复用）
async fn run_client_once(config_path: &Option<String>, strict: bool) -> Result<(), String> {
    let config = load_config_or_exit(config_path, strict);
    let path = default_config_path(config_path);

    info!(
        "Loaded config: server_addr={}, server_port={}, proxies_len={}",
        config.server_addr,
        config.server_port,
        config.proxies.len()
    );
    for (i, proxy) in config.proxies.iter().enumerate() {
        info!(
            "Proxy {}: name={}, type={}, local_port={}, remote_port={:?}",
            i, proxy.name, proxy.r#type, proxy.local_port, proxy.remote_port
        );
    }

    info!("Starting frpc client...");

    let mut client = Client::new(config, Some(path)).map_err(|e| e.to_string())?;

    // SIGHUP / 配置文件变更 / 管理端 POST /reload 的热重载统一由
    // Client::start 内部处理（共用 reload 通知通道），bin 层不再干预。
    // 管理端 POST /stop（`frpc stop`）同样由主循环统一处理。
    client.start().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_no_args_runs_client() {
        let cli = parse_args(&args(&[])).unwrap();
        assert_eq!(cli.command, Command::Run);
        assert_eq!(cli.config_path, None);
        assert!(!cli.version);
    }

    #[test]
    fn test_c_flag_only_still_runs() {
        let cli = parse_args(&args(&["-c", "my.toml"])).unwrap();
        assert_eq!(cli.command, Command::Run);
        assert_eq!(cli.config_path.as_deref(), Some("my.toml"));
    }

    #[test]
    fn test_verify_with_config() {
        let cli = parse_args(&args(&["verify", "-c", "/etc/frpc.toml"])).unwrap();
        assert_eq!(cli.command, Command::Verify);
        assert_eq!(cli.config_path.as_deref(), Some("/etc/frpc.toml"));
    }

    #[test]
    fn test_reload_status_stop() {
        let cli = parse_args(&args(&["reload"])).unwrap();
        assert_eq!(cli.command, Command::Reload);
        let cli = parse_args(&args(&["status", "-c", "x.toml"])).unwrap();
        assert_eq!(cli.command, Command::Status);
        assert_eq!(cli.config_path.as_deref(), Some("x.toml"));
        let cli = parse_args(&args(&["stop", "-c", "x.toml"])).unwrap();
        assert_eq!(cli.command, Command::Stop);
    }

    #[test]
    fn test_version_flag() {
        let cli = parse_args(&args(&["-v"])).unwrap();
        assert!(cli.version);
        let cli = parse_args(&args(&["--version", "-c", "x.toml"])).unwrap();
        assert!(cli.version);
    }

    #[test]
    fn test_config_dir_parsed() {
        let cli = parse_args(&args(&["--config_dir", "/etc/frpc.d"])).unwrap();
        assert_eq!(cli.command, Command::Run);
        assert_eq!(cli.config_dir.as_deref(), Some("/etc/frpc.d"));
    }

    #[test]
    fn test_api_timeout_units() {
        assert_eq!(
            parse_args(&args(&["status", "--api-timeout", "5"]))
                .unwrap()
                .api_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            parse_args(&args(&["status", "--api-timeout=1500ms"]))
                .unwrap()
                .api_timeout,
            Duration::from_millis(1500)
        );
        assert_eq!(
            parse_args(&args(&["status", "--api-timeout", "2m"]))
                .unwrap()
                .api_timeout,
            Duration::from_secs(120)
        );
        assert!(parse_args(&args(&["status", "--api-timeout", "abc"])).is_err());
    }

    #[test]
    fn test_unknown_arg_rejected() {
        assert!(parse_args(&args(&["--verbose"])).is_err());
    }

    #[test]
    fn test_dangling_c_rejected() {
        assert!(parse_args(&args(&["-c"])).is_err());
    }

    #[test]
    fn test_subcommand_only_valid_at_first_position() {
        // 子命令出现在非首位视为未知参数
        assert!(parse_args(&args(&["-c", "a.toml", "verify"])).is_err());
    }

    #[test]
    fn test_proxy_quick_run_flags() {
        let cli = parse_args(&args(&[
            "tcp",
            "--local_port=22",
            "--remote_port",
            "6000",
            "-s",
            "frps.example.com",
            "-p",
            "7000",
            "-t",
            "secret",
            "--use_encryption",
        ]))
        .unwrap();
        assert_eq!(cli.command, Command::Proxy("tcp".to_string()));
        assert_eq!(cli.opts.local_port, Some(22));
        assert_eq!(cli.opts.remote_port, Some(6000));
        assert_eq!(cli.opts.server_addr.as_deref(), Some("frps.example.com"));
        assert_eq!(cli.opts.server_port, Some(7000));
        assert_eq!(cli.opts.token.as_deref(), Some("secret"));
        assert!(cli.opts.use_encryption);
    }

    #[test]
    fn test_proxy_flags_accept_camel_case_and_lists() {
        let cli = parse_args(&args(&[
            "http",
            "--localPort",
            "8080",
            "--customDomains",
            "a.example.com, b.example.com",
            "--subDomain",
            "demo",
        ]))
        .unwrap();
        assert_eq!(cli.command, Command::Proxy("http".to_string()));
        assert_eq!(cli.opts.local_port, Some(8080));
        assert_eq!(
            cli.opts.custom_domains,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
        assert_eq!(cli.opts.subdomain.as_deref(), Some("demo"));
    }

    #[test]
    fn test_visitor_subcommand() {
        let cli = parse_args(&args(&[
            "stcp",
            "visitor",
            "--server_name",
            "ssh",
            "--bind_port",
            "9000",
            "--secret_key",
            "s3cr3t",
        ]))
        .unwrap();
        assert_eq!(cli.command, Command::Visitor("stcp".to_string()));
        assert_eq!(cli.opts.server_name.as_deref(), Some("ssh"));
        assert_eq!(cli.opts.bind_port, Some(9000));
        assert_eq!(cli.opts.secret_key.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn test_tcp_visitor_not_supported() {
        // tcp 无 visitor 子命令 → 第二个位置的关键字成为未知参数
        let err = parse_args(&args(&["tcp", "visitor"])).unwrap_err();
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn test_nathole_discover() {
        let cli = parse_args(&args(&[
            "nathole",
            "discover",
            "--nat_hole_stun_server",
            "stun.example.com:3478",
            "-l",
            "0.0.0.0:0",
        ]))
        .unwrap();
        assert_eq!(cli.command, Command::NatholeDiscover);
        assert_eq!(
            cli.opts.stun_server.as_deref(),
            Some("stun.example.com:3478")
        );
        assert_eq!(cli.opts.stun_local_addr.as_deref(), Some("0.0.0.0:0"));
    }

    #[test]
    fn test_nathole_requires_discover() {
        assert!(parse_args(&args(&["nathole"])).is_err());
        assert!(parse_args(&args(&["nathole", "classify"])).is_err());
    }

    #[test]
    fn test_proxy_flag_with_config_rejected() {
        // 同一次调用里既给 -c 又给代理旗标属误用
        assert!(parse_args(&args(&["-c", "a.toml", "--local_port", "22"])).is_err());
    }

    #[test]
    fn test_invalid_port_rejected() {
        assert!(parse_args(&args(&["tcp", "--local_port", "70000"])).is_err());
        assert!(parse_args(&args(&["tcp", "--local_port", "abc"])).is_err());
    }

    #[tokio::test]
    async fn test_quick_proxy_requires_local_port_or_plugin() {
        let cli = parse_args(&args(&["tcp"])).unwrap();
        let err = run_quick(&cli.command, &cli.opts).await.unwrap_err();
        assert!(err.contains("--local_port"), "unexpected: {err}");
    }

    #[tokio::test]
    async fn test_quick_visitor_requires_server_name_and_bind_port() {
        let cli = parse_args(&args(&["stcp", "visitor", "--bind_port", "9000"])).unwrap();
        let err = run_quick(&cli.command, &cli.opts).await.unwrap_err();
        assert!(err.contains("--server_name"), "unexpected: {err}");

        let cli = parse_args(&args(&["stcp", "visitor", "--server_name", "ssh"])).unwrap();
        let err = run_quick(&cli.command, &cli.opts).await.unwrap_err();
        assert!(err.contains("--bind_port"), "unexpected: {err}");
    }
}
