use std::env;
use log::{info, error};
use rust_frp_config::ConfigLoader;
use rust_frp_client::Client;

#[tokio::main]
async fn main() {
    env_logger::init();

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
