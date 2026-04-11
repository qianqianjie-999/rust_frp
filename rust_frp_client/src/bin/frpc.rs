use std::env;
use log::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_client::Client;

#[tokio::main]
async fn main() {
    // 初始化日志
    env_logger::init();

    // 解析命令行参数
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 2 && args[1] == "-c" {
        &args[2]
    } else {
        "frpc.toml"
    };

    // 加载配置
    let config = match ConfigLoader::load_client_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frpc client...");

    // 创建客户端实例
    let mut client = match Client::new(config, Some(config_path.to_string())) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create client: {:?}", e);
            return;
        }
    };

    // 启动客户端
    if let Err(e) = client.start().await {
        error!("Failed to start client: {:?}", e);
    }
}