//! FRP 客户端入口程序 (rust_frpc)
//!
//! 这是 FRP 客户端的命令行入口点，负责：
//!
//! ## 主要职责
//!
//! 1. **解析命令行参数**
//!    - 支持 `-c <config_path>` 指定配置文件
//!    - 默认配置文件：`frpc.toml`
//!
//! 2. **加载配置**
//!    - 从 TOML 文件加载客户端配置
//!    - 验证配置项
//!
//! 3. **启动客户端**
//!    - 创建 Client 实例
//!    - 调用 `client.start()` 启动客户端
//!
//! ## 使用方法
//!
//! ```bash
//! # 使用默认配置文件 frpc.toml
//! rust_frpc
//!
//! # 指定配置文件
//! rust_frpc -c /path/to/config.toml
//! ```
//!
//! ## 配置文件格式
//!
//! ```toml
//! server_addr = "127.0.0.1"
//! server_port = 9300
//!
//! [[proxies]]
//! name = "ssh"
//! type = "tcp"
//! local_ip = "127.0.0.1"
//! local_port = 22
//! remote_port = 6000
//! ```

use std::env;
use tracing::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_client::Client;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 2 && args[1] == "-c" {
        &args[2]
    } else {
        "frpc.toml"
    };

    let config = match ConfigLoader::load_client_config(config_path) {
        Ok(config) => {
            info!("Loaded config: server_addr={}, server_port={}, proxies_len={}", config.server_addr, config.server_port, config.proxies.len());
            for (i, proxy) in config.proxies.iter().enumerate() {
                info!("Proxy {}: name={}, type={}, local_port={}, remote_port={:?}", i, proxy.name, proxy.r#type, proxy.local_port, proxy.remote_port);
            }
            config
        },
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frpc client...");

    let mut client = match Client::new(config, Some(config_path.to_string())) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create client: {:?}", e);
            return;
        }
    };

    if let Err(e) = client.start().await {
        error!("Failed to start client: {:?}", e);
    }
}
