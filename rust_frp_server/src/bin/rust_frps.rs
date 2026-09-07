use rust_frp_config::ConfigLoader;
use rust_frp_server::Server;
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
        "frps.toml".to_string()
    };

    let config = match ConfigLoader::load_server_config(&config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load config: {:?}", e);
            return;
        }
    };

    info!("Starting frps server...");

    let mut server = match Server::new(config, Some(config_path.clone())).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create server: {:?}", e);
            return;
        }
    };

    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<()>(16);
    server.set_reload_rx(reload_rx);

    // 将 reload_tx 存入 server，供 WebServer API 使用
    server.set_reload_tx(reload_tx.clone());

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
            // 防抖：等待文件写入完成
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

    if let Err(e) = server.start().await {
        error!("Failed to start server: {:?}", e);
    }
}
