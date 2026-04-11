use std::env;
use std::path::Path;
use log::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_server::Server;

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::init();

    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 2 && args[1] == "-c" {
        &args[2]
    } else {
        "frps.toml"
    };

    // 加载配置
    let config = match ConfigLoader::load_server_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frps server...");

    // 创建服务器实例
    let mut server = match Server::new(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create server: {:?}", e);
            return;
        }
    };

    // 启动服务器
    if let Err(e) = server.start().await {
        error!("Failed to start server: {:?}", e);
    }
}