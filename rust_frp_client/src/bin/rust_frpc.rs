use rust_frp_client::Client;
use rust_frp_config::ConfigLoader;
use std::env;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 2 && args[1] == "-c" {
        args[2].clone()
    } else {
        "frpc.toml".to_string()
    };

    let config = match ConfigLoader::load_client_config(&config_path) {
        Ok(config) => {
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
            config
        }
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frpc client...");

    let mut client = match Client::new(config, Some(config_path.clone())) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create client: {:?}", e);
            return;
        }
    };

    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(16);

    // 启动 SIGHUP 信号处理
    if let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        let tx = reload_tx.clone();
        tokio::spawn(async move {
            loop {
                sighup.recv().await;
                info!("Received SIGHUP signal, triggering config reload...");
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
    } else {
        warn!("SIGHUP signal handler not available on this platform");
    }

    // 启动配置文件监听
    let watch_path = config_path.clone();
    let tx = reload_tx.clone();
    tokio::spawn(async move {
        use notify::{Event, EventKind, RecursiveMode, Watcher};
        let (watch_tx, mut watch_rx) = tokio::sync::mpsc::channel(1);
        let mut watcher =
            match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        let _ = watch_tx.blocking_send(());
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    warn!("Failed to create file watcher: {}", e);
                    return;
                }
            };

        if let Err(e) = watcher.watch(
            std::path::Path::new(&watch_path),
            RecursiveMode::NonRecursive,
        ) {
            warn!("Failed to watch config file {}: {}", watch_path, e);
            return;
        }
        info!("Watching config file for changes: {}", watch_path);

        loop {
            if watch_rx.recv().await.is_none() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            info!("Config file changed, triggering config reload...");
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });

    // 启动 Ctrl+C 信号处理
    if let Ok(mut sigint) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        tokio::spawn(async move {
            sigint.recv().await;
            info!("Received SIGINT, shutting down...");
            std::process::exit(0);
        });
    }

    // 服务主循环（重连 + 重载）
    let mut first_run = true;
    loop {
        if !first_run {
            info!("Reconnecting to server...");
        }
        first_run = false;

        // 处理重载信号
        let start_result = tokio::select! {
            result = client.start() => result,
            _ = reload_rx.recv() => {
                info!("Reload signal received, reloading config...");
                if let Err(e) = client.reload_config().await {
                    error!("Reload config failed: {}", e);
                }
                continue;
            }
        };

        match start_result {
            Ok(()) => {
                info!("Client stopped normally");
                break;
            }
            Err(e) => {
                error!("Client error: {:?}, reconnecting in 3 seconds...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        }
    }
}
