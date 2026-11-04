//! Server 的 vhost 相关实现（原 server.rs 的 `impl Server` 片段）。

use super::*;

impl Server {
    pub(super) async fn start_http_vhost_handler(
        &self,
        listener: &HttpVhostListener,
        http_vhost_router: Arc<HttpVhostRouter>,
        metrics: Arc<MonitorMetrics>,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
        let listener_arc = listener.get_listener();
        let proxy_owners = self.proxy_owners.clone();
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let plugin_manager = self.plugin_manager.clone();

        Ok(tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTP vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let metrics_clone = metrics.clone();
                        let po = proxy_owners.clone();
                        let cm = control_manager.clone();
                        let wcm = work_conn_manager.clone();
                        let pm = plugin_manager.clone();

                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_http_vhost_connection(conn, router, po, cm, wcm, pm)
                                    .await
                            {
                                if e.to_string().to_lowercase().contains("connection reset")
                                    || e.to_string().to_lowercase().contains("connection aborted")
                                    || e.to_string().to_lowercase().contains("broken pipe")
                                {
                                    log::debug!(
                                        "HTTP vhost connection closed (peer disconnected): {:?}",
                                        e
                                    );
                                } else {
                                    log::error!("handle http vhost connection error: {:?}", e);
                                }
                            }
                            metrics_clone.decrement_connections();
                        });
                    }
                    Err(e) => {
                        log::error!("accept HTTP vhost connection error: {:?}", e);
                        break;
                    }
                }
            }
        }))
    }

    pub(super) async fn start_https_vhost_handler(
        &self,
        listener: &HttpsVhostListener,
        http_vhost_router: Arc<HttpVhostRouter>,
        metrics: Arc<MonitorMetrics>,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
        let listener_arc = listener.get_listener();
        let tls_config = listener.tls_config.clone();
        let proxy_owners = self.proxy_owners.clone();
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let plugin_manager = self.plugin_manager.clone();

        Ok(tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTPS vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let tls_config = tls_config.clone();
                        let metrics_clone = metrics.clone();
                        let po = proxy_owners.clone();
                        let cm = control_manager.clone();
                        let wcm = work_conn_manager.clone();
                        let pm = plugin_manager.clone();

                        tokio::spawn(async move {
                            // 先进行 TLS 握手
                            match tls_config.accept(conn).await {
                                Ok(tls_conn) => {
                                    if let Err(e) = Self::handle_https_vhost_connection(
                                        tls_conn, router, po, cm, wcm, addr, pm,
                                    )
                                    .await
                                    {
                                        if e.to_string().to_lowercase().contains("connection reset")
                                            || e.to_string()
                                                .to_lowercase()
                                                .contains("connection aborted")
                                            || e.to_string().to_lowercase().contains("broken pipe")
                                        {
                                            log::debug!("HTTPS vhost connection closed (peer disconnected): {:?}", e);
                                        } else {
                                            log::error!(
                                                "handle https vhost connection error: {:?}",
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("TLS handshake error: {:?}", e);
                                }
                            }
                            metrics_clone.decrement_connections();
                        });
                    }
                    Err(e) => {
                        log::error!("accept HTTPS vhost connection error: {:?}", e);
                        break;
                    }
                }
            }
        }))
    }

    pub(super) async fn handle_http_vhost_connection(
        mut conn: tokio::net::TcpStream,
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取 HTTP 请求头
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        // 解析 HTTP 请求
        let request_info = match HttpRequestInfo::parse(&buf[..n]) {
            Some(info) => info,
            None => {
                log::warn!("failed to parse HTTP request");
                let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!(
            "HTTP request: {} {} Host: {}",
            request_info.method,
            request_info.path,
            request_info.host
        );

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router
            .find_proxy_by_host(&request_info.host)
            .await
        {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let body = format!("Proxy not found for host: {}", request_info.host);
                let content_len = body.len();
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    content_len, body
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTP request to proxy: {}", proxy_name);
        // per-proxy 连接统计守卫（drop 时自动减一）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&proxy_name)
            .map(ProxyConnGuard::acquire);

        // 服务端插件回调：NewUserConn（可拒绝本次外部接入）
        let visitor_peer = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "0.0.0.0:0".to_string());
        if let Err(reason) = crate::proxy_manager::notify_new_user_conn(
            &plugin_manager,
            &control_manager,
            &proxy_owners,
            proxy_name.as_str(),
            "http",
            &visitor_peer,
        )
        .await
        {
            log::warn!(
                "HTTP user conn from {} for proxy [{}] rejected by http plugin: {}",
                visitor_peer,
                proxy_name,
                reason
            );
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 查找代理对应的 run_id
        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&proxy_name).cloned()
        };

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for HTTP proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 获取对应的消息通道
        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 从池中获取工作连接
        let visitor_addr = conn.peer_addr().unwrap_or_else(|_| {
            "0.0.0.0:0"
                .parse()
                .expect("constant socket addr is always valid")
        });
        match work_conn_manager
            .get_work_conn(&proxy_name, &msg_tx, Duration::from_secs(30), visitor_addr)
            .await
        {
            Ok(mut work_conn) => {
                log::info!("Got work conn for HTTP proxy {}, bridging", proxy_name);
                // 先发送已读取的 HTTP 数据到工作连接
                if n > 0 {
                    if let Err(e) = work_conn.write_all(&buf[..n]).await {
                        log::error!("Failed to write initial HTTP data to work conn: {:?}", e);
                        return Ok(());
                    }
                }
                // 桥接剩余数据
                match rust_frp_util::bridge_streams_counted(conn, work_conn).await {
                    Ok((to_work, to_visitor)) => {
                        global_metrics().record_traffic(&proxy_name, to_work, to_visitor);
                    }
                    Err(e) => rust_frp_util::log_bridge_error("HTTP bridge error", e.as_ref()),
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to get work conn for HTTP proxy {}: {}",
                    proxy_name,
                    e
                );
                let response = "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
        }

        Ok(())
    }

    pub(super) async fn handle_https_vhost_connection<S>(
        mut conn: S,
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        visitor_addr: std::net::SocketAddr,
        plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // 读取 HTTP 请求头（来自 TLS 解密后的数据）
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        // 解析 HTTP 请求
        let request_info = match HttpRequestInfo::parse(&buf[..n]) {
            Some(info) => info,
            None => {
                log::warn!("failed to parse HTTPS request");
                let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!(
            "HTTPS request: {} {} Host: {}",
            request_info.method,
            request_info.path,
            request_info.host
        );

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router
            .find_proxy_by_host(&request_info.host)
            .await
        {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let body = format!("Proxy not found for host: {}", request_info.host);
                let content_len = body.len();
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    content_len, body
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTPS request to proxy: {}", proxy_name);
        // per-proxy 连接统计守卫（drop 时自动减一）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&proxy_name)
            .map(ProxyConnGuard::acquire);

        // 服务端插件回调：NewUserConn（可拒绝本次外部接入）
        let visitor_peer = visitor_addr.to_string();
        if let Err(reason) = crate::proxy_manager::notify_new_user_conn(
            &plugin_manager,
            &control_manager,
            &proxy_owners,
            proxy_name.as_str(),
            "https",
            &visitor_peer,
        )
        .await
        {
            log::warn!(
                "HTTPS user conn from {} for proxy [{}] rejected by http plugin: {}",
                visitor_peer,
                proxy_name,
                reason
            );
            let response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 查找代理对应的 run_id
        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&proxy_name).cloned()
        };

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for HTTPS proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 获取对应的消息通道
        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 从池中获取工作连接
        match work_conn_manager
            .get_work_conn(&proxy_name, &msg_tx, Duration::from_secs(30), visitor_addr)
            .await
        {
            Ok(work_conn) => {
                log::info!("Got work conn for HTTPS proxy {}, bridging", proxy_name);
                // 先发送已读取的 HTTP 数据到工作连接
                // 注意：对于 HTTPS，conn 是 TLS 流，work_conn 是普通 TCP
                // 我们先写已读数据，然后用 bridge_streams 桥接 TLS 流和 TCP 流
                let initial_data = buf[..n].to_vec();
                let mut work_conn_clone = work_conn;
                if !initial_data.is_empty() {
                    if let Err(e) = work_conn_clone.write_all(&initial_data).await {
                        log::error!("Failed to write initial HTTPS data to work conn: {:?}", e);
                        return Ok(());
                    }
                }
                // 使用 bridge_streams 桥接 TLS 流和 TCP 流
                match rust_frp_util::bridge_streams_counted(conn, work_conn_clone).await {
                    Ok((to_work, to_visitor)) => {
                        global_metrics().record_traffic(&proxy_name, to_work, to_visitor);
                    }
                    Err(e) => rust_frp_util::log_bridge_error("HTTPS bridge error", e.as_ref()),
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to get work conn for HTTPS proxy {}: {}",
                    proxy_name,
                    e
                );
                let response = "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
        }

        Ok(())
    }
}
