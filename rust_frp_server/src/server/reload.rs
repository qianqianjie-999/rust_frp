//! 配置热加载辅助函数（原 server.rs 中 `reload_server_config`）。

use super::*;

/// 从配置文件重载服务端配置（独立函数，避免 select! 中的借用冲突）
pub(crate) async fn reload_server_config(
    config_path: &Option<String>,
    config: &mut ServerConfig,
    auth_runtime: &AuthRuntime,
    proxy_manager: &Arc<ServerProxyManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = config_path {
        log::info!("Reloading config from: {}", path);
        let new_config = rust_frp_config::ConfigLoader::load_server_config(path)?;

        *config = new_config;
        *auth_runtime.write().await =
            Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        // ProxyManager 持有自己的 allow_ports 副本，必须显式同步（评审实测：
        // 重载后新白名单不生效，代理注册仍按旧列表拒绝）
        proxy_manager
            .set_allow_ports(config.allow_ports.clone())
            .await;

        log::info!("Config reloaded successfully");
    }
    Ok(())
}
