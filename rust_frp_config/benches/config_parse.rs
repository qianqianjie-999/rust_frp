//! 配置解析基准（零额外依赖，直接用 std::time 计时）。
//!
//! 运行：`cargo bench -p rust_frp_config`
//!
//! 关注点：TOML 主路径的解析 + 校验耗时，单位为 µs/op。回归判断标准是
//! 同一台机器上相对基线的变化，而不是绝对值。

use rust_frp_config::{ClientConfig, ConfigLoader, ServerConfig};
use std::time::{Duration, Instant};

const SERVER_TOML: &str = r#"
bind_addr = "0.0.0.0"
bind_port = 7000
work_conn_port = 7001
vhost_http_port = 8080
vhost_https_port = 8443
allow_ports = [
    { start = 6000, end = 7000 },
    { single = 8080 },
    { single = 8443 },
]
log = { to = "console", level = "info", max_days = 7 }

[auth]
method = "token"
token = "bench-token"

[transport]
tls = { enable = true }
max_pool_count = 4
"#;

const CLIENT_TOML: &str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth]
method = "token"
token = "bench-token"

[log]
to = "console"
level = "info"

[transport]
tls = { enable = true }
pool_count = 0
tcp_keepalive_secs = 30

[[proxies]]
name = "web"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8000
remote_port = 6000

[[proxies]]
name = "files"
type = "http"
local_ip = "127.0.0.1"
local_port = 8080
custom_domains = ["files.example.com"]
"#;

fn bench<T>(
    label: &str,
    iters: u32,
    mut run: impl FnMut() -> Result<T, Box<dyn std::error::Error>>,
) {
    // 预热，避免把首次解析的冷启动开销算进均值
    for _ in 0..(iters / 10).max(1) {
        let _ = run();
    }
    let start = Instant::now();
    let mut ok = 0u32;
    let mut first_err: Option<String> = None;
    for _ in 0..iters {
        match run() {
            Ok(_) => ok += 1,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
            }
        }
    }
    let elapsed = start.elapsed();
    let per_op: Duration = elapsed / iters;
    println!("{label}: {per_op:?}/op（{iters} 次，总 {elapsed:?}，成功 {ok} 次）");
    if let Some(err) = first_err {
        println!("  首个错误：{err}");
    }
}

fn main() {
    let iters = 2000;

    bench("server.toml 解析+校验", iters, || {
        ConfigLoader::validate_server_config_content(SERVER_TOML).map(|c: ServerConfig| c.bind_port)
    });

    bench("client.toml 解析+校验", iters, || {
        ConfigLoader::validate_client_config_content(CLIENT_TOML)
            .map(|c: ClientConfig| c.server_port)
    });

    bench("server.toml 严格模式解析", iters, || {
        ConfigLoader::validate_server_config_content_strict(SERVER_TOML, true)
            .map(|c: ServerConfig| c.bind_port)
    });
}
