//! FRP 服务器入口程序 (rust_frps)
//!
//! 这是 FRP 服务器的命令行入口点，负责：
//!
//! ## 主要职责
//!
//! 1. **解析命令行参数**
//!    - 支持 `-c <config_path>` 指定配置文件
//!    - 默认配置文件：`frps.toml`
//!
//! 2. **加载配置**
//!    - 从 TOML 文件加载服务器配置
//!    - 验证配置项
//!
//! 3. **启动服务器**
//!    - 创建 Server 实例
//!    - 调用 `server.start()` 启动服务器
//!
//! ## 使用方法
//!
//! ```bash
//! # 使用默认配置文件 frps.toml
//! rust_frps
//!
//! # 指定配置文件
//! rust_frps -c /path/to/config.toml
//! ```
//!
//! ## 配置文件格式
//!
//! ```toml
//! bind_addr = "0.0.0.0"
//! bind_port = 9300
//!
//! [web_server]
//! addr = "0.0.0.0"
//! port = 7500
//! user = "admin"
//! password = "admin"
//!
//! [auth]
//! method = "token"
//! token = "your_secure_token"
//!
//! allow_ports = [
//!     { single = 9302 },
//!     { start = 10000, end = 20000 },
//! ]
//! ```
//!
//! ## 安全建议
//!
//! - 生产环境务必修改默认 token
//! - 配置 `allow_ports` 限制可使用的端口范围
//! - 启用 TLS 加密传输

use std::env;
use tracing::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_server::Server;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 2 && args[1] == "-c" {
        &args[2]
    } else {
        "frps.toml"
    };

    let config = match ConfigLoader::load_server_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frps server...");

    let mut server = match Server::new(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create server: {:?}", e);
            return;
        }
    };

    if let Err(e) = server.start().await {
        error!("Failed to start server: {:?}", e);
    }
}
