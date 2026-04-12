use std::env;
use log::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_server::Server;

#[tokio::main]
async fn main() {
    env_logger::init();

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
