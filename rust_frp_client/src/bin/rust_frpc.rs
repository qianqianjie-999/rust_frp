use rust_frp_client::{admin_client::admin_http_request, Client};
use rust_frp_config::ConfigLoader;
use std::process::exit;
use tracing::{error, info};

/// frpc 子命令
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// 默认：前台运行客户端
    Run,
    /// 校验配置文件（语法 + 校验规则），不连接服务端
    Verify,
    /// 请求运行中的 frpc 热重载配置（走管理端口 POST /reload）
    Reload,
    /// 查询运行中的 frpc 代理状态（走管理端口 GET /status）
    Status,
}

struct CliArgs {
    command: Command,
    config_path: Option<String>,
}

/// 解析命令行参数。
///
/// 支持的形式（与 frp 原版一致）：
/// - `frpc [-c path]`                    运行
/// - `frpc verify [-c path]`             校验配置
/// - `frpc reload [-c path]`             热重载
/// - `frpc status [-c path]`             查询状态
fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut command = Command::Run;
    let mut config_path: Option<String> = None;
    let mut expect_config = false;

    for (i, arg) in args.iter().enumerate() {
        if expect_config {
            config_path = Some(arg.clone());
            expect_config = false;
            continue;
        }
        match arg.as_str() {
            // 子命令只允许出现在第一个位置
            "verify" if i == 0 => command = Command::Verify,
            "reload" if i == 0 => command = Command::Reload,
            "status" if i == 0 => command = Command::Status,
            "-c" | "--config" => expect_config = true,
            other => {
                return Err(format!(
                    "unknown argument: {other}\nusage: frpc [verify|reload|status] [-c config_path]"
                ))
            }
        }
    }

    if expect_config {
        return Err("-c/--config requires a path".to_string());
    }
    Ok(CliArgs {
        command,
        config_path,
    })
}

const USAGE: &str = "usage: frpc [verify|reload|status] [-c config_path]";

/// 加载配置；失败打印错误并以退出码 1 结束
fn load_config_or_exit(config_path: &Option<String>) -> rust_frp_config::ClientConfig {
    let path = config_path
        .clone()
        .unwrap_or_else(|| "frpc.toml".to_string());
    match ConfigLoader::load_client_config(&path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("frpc: load config from {path} failed: {e}");
            exit(1);
        }
    }
}

/// `frpc verify`：校验配置文件后按结果设置退出码
fn run_verify(config_path: &Option<String>) {
    let path = config_path
        .clone()
        .unwrap_or_else(|| "frpc.toml".to_string());
    match ConfigLoader::load_client_config(&path) {
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

/// `frpc reload` / `frpc status`：请求管理端口并打印响应
async fn run_admin(config_path: &Option<String>, method: &str, path: &str) {
    let config = load_config_or_exit(config_path);
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

    match admin_http_request(&ws.addr, ws.port, method, path, auth).await {
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("frpc: {e}\n{USAGE}");
            exit(2);
        }
    };

    match cli.command {
        Command::Verify => run_verify(&cli.config_path),
        Command::Reload => run_admin(&cli.config_path, "POST", "/reload").await,
        Command::Status => run_admin(&cli.config_path, "GET", "/status").await,
        Command::Run => run_client(&cli.config_path).await,
    }
}

/// 默认运行模式：启动客户端主循环
async fn run_client(config_path: &Option<String>) {
    let config = load_config_or_exit(config_path);
    let config_path = config_path
        .clone()
        .unwrap_or_else(|| "frpc.toml".to_string());

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

    let mut client = match Client::new(config, Some(config_path.clone())) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create client: {:?}", e);
            exit(1);
        }
    };

    // SIGHUP / 配置文件变更 / 管理端 POST /reload 的热重载统一由
    // Client::start 内部处理（共用 reload 通知通道），bin 层不再干预

    if let Err(e) = client.start().await {
        error!("Client error: {:?}", e);
        exit(1);
    }
    info!("Client stopped normally");
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
    fn test_reload_and_status() {
        let cli = parse_args(&args(&["reload"])).unwrap();
        assert_eq!(cli.command, Command::Reload);
        let cli = parse_args(&args(&["status", "-c", "x.toml"])).unwrap();
        assert_eq!(cli.command, Command::Status);
        assert_eq!(cli.config_path.as_deref(), Some("x.toml"));
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
}
