//! 代理管理：注册、端口分配、监听器生命周期与分组

use rust_frp_core::{Message, ProxyManager};
use rust_frp_net::WebSocketConn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;

use crate::*;

pub(crate) type ListenerMap = Arc<
    RwLock<
        std::collections::HashMap<
            String,
            (
                std::sync::Arc<tokio::net::TcpListener>,
                std::sync::Arc<std::sync::atomic::AtomicBool>,
            ),
        >,
    >,
>;

/// UDP 代理会话信息，用于跟踪访问者地址以便回传响应
#[derive(Debug, Clone)]
pub(crate) struct UdpProxySession {
    socket: Arc<tokio::net::UdpSocket>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) type UdpSocketMap = Arc<RwLock<std::collections::HashMap<String, UdpProxySession>>>;

/// 组共享监听器在 listeners / accept_handles 中的键（与代理名空间隔离）
pub(crate) fn group_listener_key(port: u16) -> String {
    format!("__group_port_{}__", port)
}

/// TCP 代理负载均衡分组状态
pub(crate) struct GroupState {
    /// 组名
    group: String,
    /// 组密钥（加入时校验，防止误入他人分组）
    group_key: String,
    /// 成员代理名（注册顺序）
    members: Vec<String>,
    /// round-robin 轮询索引
    rr_index: usize,
}

/// TCP 代理负载均衡分组注册表
///
/// 同 group + 同 remote_port 的代理共享一个监听端口：
/// 首成员绑定端口并启动 accept 循环，后续成员仅注册成员身份；
/// 新连接按 round-robin 选取成员处理（对齐 frp group 语义）。
///
/// 组名全局唯一（同名组不允许绑定不同端口）。
#[derive(Default)]
pub struct GroupRegistry {
    /// 端口 -> 组状态
    groups: RwLock<std::collections::HashMap<u16, GroupState>>,
    /// 组名 -> 端口（组名唯一性索引）
    group_ports: RwLock<std::collections::HashMap<String, u16>>,
}

impl GroupRegistry {
    fn new() -> Self {
        Self::default()
    }

    /// 加入组；返回 `true` 表示本代理是首成员（需要绑定监听端口）
    ///
    /// 错误场景（对齐 frp ErrGroupAuthFailed / ErrGroupDifferentPort）：
    /// - 同组名绑定不同端口
    /// - 同端口已被其他组占用
    /// - group_key 与已有成员不匹配
    pub async fn join(
        &self,
        group: &str,
        group_key: &str,
        port: u16,
        proxy_name: &str,
    ) -> Result<bool, String> {
        // 组名唯一性：同组名不允许绑定不同端口
        {
            let group_ports = self.group_ports.read().await;
            if let Some(&bound) = group_ports.get(group) {
                if bound != port {
                    return Err(format!(
                        "group [{}] is bound to port {}, cannot join port {}",
                        group, bound, port
                    ));
                }
            }
        }

        let mut groups = self.groups.write().await;
        match groups.get_mut(&port) {
            Some(state) => {
                if state.group != group {
                    return Err(format!(
                        "port {} is already bound by group [{}]",
                        port, state.group
                    ));
                }
                if state.group_key != group_key {
                    return Err(format!("group [{}] auth failed: group_key mismatch", group));
                }
                state.members.push(proxy_name.to_string());
                log::info!(
                    "proxy [{}] joined group [{}] on port {} ({} members)",
                    proxy_name,
                    group,
                    port,
                    state.members.len()
                );
                Ok(false)
            }
            None => {
                groups.insert(
                    port,
                    GroupState {
                        group: group.to_string(),
                        group_key: group_key.to_string(),
                        members: vec![proxy_name.to_string()],
                        rr_index: 0,
                    },
                );
                self.group_ports
                    .write()
                    .await
                    .insert(group.to_string(), port);
                log::info!(
                    "proxy [{}] is first member of group [{}] on port {}",
                    proxy_name,
                    group,
                    port
                );
                Ok(true)
            }
        }
    }

    /// 退出组；返回 `true` 表示组已空（应关闭共享监听器）
    pub async fn leave(&self, port: u16, proxy_name: &str) -> bool {
        let mut groups = self.groups.write().await;
        let empty = match groups.get_mut(&port) {
            Some(state) => {
                state.members.retain(|m| m != proxy_name);
                state.members.is_empty()
            }
            None => false,
        };
        if empty {
            if let Some(state) = groups.remove(&port) {
                self.group_ports.write().await.remove(&state.group);
                log::info!("group [{}] on port {} is empty", state.group, port);
            }
        }
        empty
    }

    /// round-robin 选取一个成员处理新连接
    pub async fn pick(&self, port: u16) -> Option<String> {
        let mut groups = self.groups.write().await;
        let state = groups.get_mut(&port)?;
        if state.members.is_empty() {
            return None;
        }
        let name = state.members[state.rr_index % state.members.len()].clone();
        state.rr_index = state.rr_index.wrapping_add(1);
        Some(name)
    }

    /// 组当前成员数（日志/调试用）
    pub async fn member_count(&self, port: u16) -> usize {
        self.groups
            .read()
            .await
            .get(&port)
            .map(|s| s.members.len())
            .unwrap_or(0)
    }
}

/// TCP 访客桥接依赖集合（accept 循环按连接克隆，字段均为 Arc 廉价拷贝）
pub(crate) struct TcpVisitorDeps {
    pub proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub control_manager: Arc<ControlManager>,
    pub work_conn_manager: Arc<ServerWorkConnManager>,
    pub plugin_config: Option<rust_frp_config::PluginConfig>,
    pub group_registry: Arc<GroupRegistry>,
    pub plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

/// 触发 NewUserConn 插件回调；返回 `Err` 表示本次外部接入被拒绝。
///
/// 供 TCP / WebSocket / HTTP(S) vhost / tcpmux 各用户连接入口共用：
/// 通过 `proxy_owners` 反查代理归属的 run_id，再取用户名填充 UserInfo。
pub(crate) async fn notify_new_user_conn(
    plugin_manager: &rust_frp_plugin::server_plugin::Manager,
    control_manager: &ControlManager,
    proxy_owners: &RwLock<std::collections::HashMap<String, String>>,
    proxy_name: &str,
    proxy_type: &str,
    remote_addr: &str,
) -> Result<(), String> {
    if plugin_manager.is_empty() {
        return Ok(());
    }
    let run_id = proxy_owners
        .read()
        .await
        .get(proxy_name)
        .cloned()
        .unwrap_or_default();
    let user = if run_id.is_empty() {
        String::new()
    } else {
        control_manager
            .get_user_by_run_id(&run_id)
            .await
            .unwrap_or_default()
    };
    let content = serde_json::json!({
        "user": { "user": user, "run_id": run_id, "metas": {} },
        "proxy_name": proxy_name,
        "proxy_type": proxy_type,
        "remote_addr": remote_addr,
    });
    plugin_manager.new_user_conn(&content).await
}

pub struct ServerProxyManager {
    pub(crate) proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: ListenerMap,
    udp_sessions: UdpSocketMap,
    http_vhost_router: Arc<HttpVhostRouter>,
    /// 代理所有权映射 (proxy_name -> run_id)
    pub(crate) proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// 控制器管理器
    control_manager: Arc<ControlManager>,
    /// 工作连接管理器
    work_conn_manager: Arc<ServerWorkConnManager>,
    /// 允许的端口列表（空列表 = 默认拒绝所有）
    allow_ports: Vec<rust_frp_config::PortRange>,
    /// 单用户最大端口配额（None = 不限制，对应 max_ports_per_user 配置）
    max_ports_per_user: Option<usize>,
    /// 用户已占用端口计数 (user -> ports_used)
    user_port_counts: RwLock<std::collections::HashMap<String, usize>>,
    /// 代理归属与端口占用记录 (proxy_name -> (user, ports_used))，用于移除时释放配额
    proxy_user_ports: RwLock<std::collections::HashMap<String, (String, usize)>>,
    /// accept 任务的 JoinHandle，用于 stop_proxy 时立即中止
    accept_handles: RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    /// TCP 负载均衡分组注册表（group 代理共享监听端口，round-robin 分发）
    group_registry: Arc<GroupRegistry>,
    /// tcpmux 路由表（域名 + 可选 HTTP 用户 → tcpmux 代理）
    tcpmux_router: Arc<TcpMuxRouter>,
    /// tcpmux 复用端口（None = 未启用，注册 tcpmux 代理时告警）
    tcpmux_port: Option<u16>,
    /// 服务端 HTTP 插件管理器（控制面回调；未配置插件时为空管理器）
    plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

/// [`ServerProxyManager::new`] 的可选配置项（收敛参数列表，避免超长签名）
pub struct ProxyManagerOptions {
    /// 允许的端口范围（空 = 默认拒绝所有 TCP/UDP 代理端口）
    pub allow_ports: Vec<rust_frp_config::PortRange>,
    /// 单用户最大端口数
    pub max_ports_per_user: Option<usize>,
    /// tcpmux HTTP CONNECT 复用端口
    pub tcpmux_port: Option<u16>,
    /// 服务端 HTTP 插件管理器
    pub plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

/// 检查端口是否在允许列表中
pub(crate) fn port_allowed(port: u16, ranges: &[rust_frp_config::PortRange]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    for range in ranges {
        // 单端口匹配
        if let Some(single) = range.single {
            if port == single {
                return true;
            }
        }
        // 范围匹配：start/end 均显式配置时才按范围判定。
        // 修复：此前 start/end 缺省 0/65535，导致 { single = x } 条目
        // 实际放行全部端口，白名单形同虚设。
        if let (Some(start), Some(end)) = (range.start, range.end) {
            if port >= start && port <= end {
                return true;
            }
        }
    }
    false
}

/// 汇总 tcpmux 代理的域名（custom_domains 优先，附加 subdomain）
fn build_tcpmux_domains(config: &rust_frp_config::ProxyConfig) -> Vec<String> {
    let mut domains = config.custom_domains.clone().unwrap_or_default();
    domains.extend(config.subdomain.clone());
    domains.retain(|d| !d.is_empty());
    domains
}

impl ServerProxyManager {
    pub fn new(
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        options: ProxyManagerOptions,
    ) -> Self {
        let ProxyManagerOptions {
            allow_ports,
            max_ports_per_user,
            tcpmux_port,
            plugin_manager,
        } = options;
        if allow_ports.is_empty() {
            log::warn!(
                "allow_ports is empty, all TCP proxy ports will be rejected. \
                 Please configure allow_ports in frps.toml to specify allowed port ranges."
            );
        }
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: Arc::new(RwLock::new(std::collections::HashMap::new())),
            udp_sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            http_vhost_router,
            proxy_owners,
            control_manager,
            work_conn_manager,
            allow_ports,
            max_ports_per_user,
            user_port_counts: RwLock::new(std::collections::HashMap::new()),
            proxy_user_ports: RwLock::new(std::collections::HashMap::new()),
            accept_handles: RwLock::new(std::collections::HashMap::new()),
            group_registry: Arc::new(GroupRegistry::new()),
            tcpmux_router: Arc::new(TcpMuxRouter::new()),
            tcpmux_port,
            plugin_manager,
        }
    }

    /// 服务端 HTTP 插件管理器（供 vhost / tcpmux 等用户连接入口回调）
    pub fn plugin_manager(&self) -> Arc<rust_frp_plugin::server_plugin::Manager> {
        self.plugin_manager.clone()
    }

    pub async fn start_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => self.start_tcp_proxy(config).await?,
            "http" => self.register_vhost_proxy(config, "HTTP").await?,
            "https" => self.register_vhost_proxy(config, "HTTPS").await?,
            "udp" => self.start_udp_proxy(config).await?,
            "websocket" => self.start_websocket_proxy(config).await?,
            "tcpmux" => self.register_tcpmux_proxy(config).await?,
            "sudp" => {
                // sudp 与 stcp 同构：不绑定端口，仅作为访问者监听器等待
                // frpc visitor 经 STCP 通道请求建桥（UDP 报文由两端 frpc 自行封装）
                if config.secret_key.as_deref().unwrap_or("").is_empty() {
                    log::warn!(
                        "sudp proxy {} has no secret_key configured; visitor access will be rejected",
                        config.name
                    );
                }
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
            }
        }
        Ok(())
    }

    /// tcpmux 代理：注册域名路由，实际监听由服务端的 tcpmux 复用器统一承担
    async fn register_tcpmux_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // multiplexer 目前仅支持 httpconnect（缺省即 httpconnect）
        if let Some(multiplexer) = config.multiplexer.as_deref() {
            if !multiplexer.is_empty() && multiplexer != "httpconnect" {
                return Err(format!(
                    "proxy [{}] rejected: unknown multiplexer [{}] (only \"httpconnect\" is supported)",
                    config.name, multiplexer
                )
                .into());
            }
        }

        if self.tcpmux_port.is_none() {
            return Err(format!(
                "proxy [{}] rejected: tcpmux requires server-side tcpmux_http_connect_port",
                config.name
            )
            .into());
        }

        let domains = build_tcpmux_domains(config);
        if domains.is_empty() {
            return Err(format!(
                "proxy [{}] rejected: tcpmux requires custom_domains or subdomain",
                config.name
            )
            .into());
        }

        let route = TcpMuxRoute {
            proxy_name: config.name.clone(),
            http_user: config.http_user.clone(),
            http_password: config.http_password.clone(),
            route_by_http_user: config.route_by_http_user.clone(),
        };
        log::info!(
            "tcpmux proxy {} registered for domains {:?}",
            config.name,
            domains
        );
        self.tcpmux_router.register(domains, route).await;
        Ok(())
    }

    /// TCP 代理：绑定远端端口，accept 循环（分组分发 / 插件 / 工作连接桥接）
    async fn start_tcp_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(remote_port) = config.remote_port {
            // 检查端口是否在允许列表中（空列表 = 默认拒绝所有）
            if !port_allowed(remote_port, &self.allow_ports) {
                return Err(
                    format!("Port {} is not in the allowed ports list", remote_port).into(),
                );
            }

            // 负载均衡分组：加入组；首成员绑定端口，后续成员共享监听器
            let group_port = if let Some(ref group) = config.group {
                let group_key = config.group_key.clone().unwrap_or_default();
                let first = self
                    .group_registry
                    .join(group, &group_key, remote_port, &config.name)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                if !first {
                    // 共享已有监听器，本成员无需绑定
                    return Ok(());
                }
                Some(remote_port)
            } else {
                None
            };

            let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let proxy_name = config.name.clone();
            let listeners = self.listeners.clone();

            // 使用Arc来共享listener
            let listener_arc = std::sync::Arc::new(listener);
            let listener_clone = listener_arc.clone();

            // 创建一个原子布尔值来控制任务的运行
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();

            // 共享状态用于工作连接协议
            let proxy_owners = self.proxy_owners.clone();
            let control_manager = self.control_manager.clone();
            let work_conn_manager = self.work_conn_manager.clone();
            let plugin_config = config.plugin.clone();
            // 分组分发：accept 循环内 round-robin 选取成员
            let group_registry = self.group_registry.clone();
            let plugin_manager = self.plugin_manager.clone();
            let handle = tokio::spawn(async move {
                while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    match listener_clone.accept().await {
                        Ok((visitor_conn, visitor_addr)) => {
                            log::info!(
                                "new TCP connection for proxy {} from {}",
                                proxy_name,
                                visitor_addr
                            );

                            let proxy_name_clone = proxy_name.clone();
                            let deps = TcpVisitorDeps {
                                proxy_owners: proxy_owners.clone(),
                                control_manager: control_manager.clone(),
                                work_conn_manager: work_conn_manager.clone(),
                                plugin_config: plugin_config.clone(),
                                group_registry: group_registry.clone(),
                                plugin_manager: plugin_manager.clone(),
                            };
                            tokio::spawn(ServerProxyManager::serve_tcp_visitor(
                                proxy_name_clone,
                                group_port,
                                visitor_conn,
                                visitor_addr,
                                deps,
                            ));
                        }
                        Err(e) => {
                            log::error!("accept TCP connection error: {:?}", e);
                            break;
                        }
                    }
                }
                log::info!("TCP proxy {} stopped", proxy_name);
            });

            // 分组代理的监听器按组端口键存储（与代理名空间隔离，
            // 成员进出不影响共享监听器；组空时由 stop_proxy 清理）
            let listener_key = match group_port {
                Some(port) => group_listener_key(port),
                None => config.name.clone(),
            };
            let mut listeners = listeners.write().await;
            listeners.insert(listener_key.clone(), (listener_arc, running));
            let mut handles = self.accept_handles.write().await;
            handles.insert(listener_key, handle);
        }
        Ok(())
    }

    /// HTTP/HTTPS 代理：注册到虚拟主机路由器（custom_domains + subdomain）
    async fn register_vhost_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
        kind: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut domains = Vec::new();

        if let Some(custom_domains) = &config.custom_domains {
            domains.extend(custom_domains.clone());
        }

        if let Some(subdomain) = &config.subdomain {
            domains.push(subdomain.clone());
        }

        if !domains.is_empty() {
            self.http_vhost_router
                .register_proxy(config.name.clone(), domains, config.clone())
                .await;
            log::info!(
                "{} proxy {} registered with domains: {:?}",
                kind,
                config.name,
                config.custom_domains
            );
        } else {
            log::warn!("{} proxy {} has no domains configured", kind, config.name);
        }
        Ok(())
    }

    /// UDP 代理：绑定远端端口，收包转 UdpPacket 消息给对应客户端
    async fn start_udp_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(remote_port) = config.remote_port {
            if !port_allowed(remote_port, &self.allow_ports) {
                return Err(
                    format!("Port {} is not in the allowed ports list", remote_port).into(),
                );
            }
            let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
            let socket = tokio::net::UdpSocket::bind(&addr).await?;
            let socket = Arc::new(socket);
            let socket_clone = socket.clone();
            let proxy_name = config.name.clone();
            let proxy_owners = self.proxy_owners.clone();
            let control_manager = self.control_manager.clone();
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();

            self.udp_sessions.write().await.insert(
                config.name.clone(),
                UdpProxySession {
                    socket: socket.clone(),
                    running: running.clone(),
                },
            );

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        socket_clone.recv_from(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok((n, src_addr))) => {
                            let data = buf[..n].to_vec();
                            let run_id = {
                                let owners = proxy_owners.read().await;
                                owners.get(&proxy_name).cloned()
                            };
                            if let Some(run_id) = run_id {
                                if let Some(msg_tx) = control_manager.get_msg_tx(&run_id).await {
                                    let udp_msg = rust_frp_core::UdpPacketMsg {
                                        proxy_name: proxy_name.clone(),
                                        data,
                                        client_addr: Some(src_addr.to_string()),
                                    };
                                    let _ = msg_tx.send(Message::UdpPacket(udp_msg)).await;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            log::error!("UDP recv error for proxy {}: {:?}", proxy_name, e);
                            break;
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }
                log::info!("UDP proxy {} stopped", proxy_name);
            });

            log::info!("UDP proxy {} listening on {}", config.name, addr);
        } else {
            return Err("UDP proxy requires remote_port".into());
        }
        Ok(())
    }

    /// WebSocket 代理：绑定远端端口，accept 循环（WS 升级 + 工作连接桥接）
    async fn start_websocket_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(remote_port) = config.remote_port {
            if !port_allowed(remote_port, &self.allow_ports) {
                return Err(
                    format!("Port {} is not in the allowed ports list", remote_port).into(),
                );
            }
            let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let proxy_name = config.name.clone();
            let listeners = self.listeners.clone();
            let listener_arc = std::sync::Arc::new(listener);
            let listener_clone = listener_arc.clone();
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_clone = running.clone();
            let proxy_owners = self.proxy_owners.clone();
            let control_manager = self.control_manager.clone();
            let work_conn_manager = self.work_conn_manager.clone();
            let plugin_manager = self.plugin_manager.clone();
            let handle = tokio::spawn(async move {
                while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    match listener_clone.accept().await {
                        Ok((visitor_conn, visitor_addr)) => {
                            log::info!(
                                "new WebSocket connection for proxy {} from {}",
                                proxy_name,
                                visitor_addr
                            );

                            let proxy_name_clone = proxy_name.clone();
                            let proxy_owners = proxy_owners.clone();
                            let control_manager = control_manager.clone();
                            let work_conn_manager = work_conn_manager.clone();
                            let plugin_manager = plugin_manager.clone();

                            tokio::spawn(ServerProxyManager::serve_websocket_visitor(
                                proxy_name_clone,
                                visitor_conn,
                                visitor_addr,
                                proxy_owners,
                                control_manager,
                                work_conn_manager,
                                plugin_manager,
                            ));
                        }
                        Err(e) => {
                            log::error!("accept WebSocket connection error: {:?}", e);
                            break;
                        }
                    }
                }
                log::info!("WebSocket proxy {} stopped", proxy_name);
            });

            let mut listeners = listeners.write().await;
            listeners.insert(config.name.clone(), (listener_arc, running));
            let mut handles = self.accept_handles.write().await;
            handles.insert(config.name.clone(), handle);
        }
        Ok(())
    }

    /// 处理单个 TCP 访客连接：分组分发 / 插件处理 / 工作连接桥接（由 accept 循环 spawn）
    async fn serve_tcp_visitor(
        proxy_name_clone: String,
        group_port: Option<u16>,
        visitor_conn: tokio::net::TcpStream,
        visitor_addr: SocketAddr,
        deps: TcpVisitorDeps,
    ) {
        let TcpVisitorDeps {
            proxy_owners,
            control_manager,
            work_conn_manager,
            plugin_config,
            group_registry,
            plugin_manager,
        } = deps;
        log::debug!("开始处理外部连接: proxy={}", proxy_name_clone);

        // 负载均衡分组：round-robin 选取实际处理连接的成员
        let target_name = if let Some(port) = group_port {
            match group_registry.pick(port).await {
                Some(name) => {
                    log::debug!(
                        "group port {} picked member [{}] (connection from {})",
                        port,
                        name,
                        visitor_addr
                    );
                    name
                }
                None => {
                    log::error!("group on port {} has no available members", port);
                    let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nNo available group members");
                    return;
                }
            }
        } else {
            proxy_name_clone.clone()
        };

        // per-proxy 连接统计守卫（drop 时自动减一，按实际服务成员计）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&target_name)
            .map(ProxyConnGuard::acquire);

        // 服务端插件回调：NewUserConn（可拒绝本次外部接入）
        if let Err(reason) = notify_new_user_conn(
            &plugin_manager,
            &control_manager,
            &proxy_owners,
            target_name.as_str(),
            "tcp",
            &visitor_addr.to_string(),
        )
        .await
        {
            log::warn!(
                "User conn from {} for proxy [{}] rejected by http plugin: {}",
                visitor_addr,
                target_name,
                reason
            );
            return;
        }

        // 检查是否有插件配置（插件直接处理访问者连接，不需要工作连接）
        if let Some(ref pconf) = plugin_config {
            log::debug!("使用插件处理连接: proxy={}", proxy_name_clone);
            let plugin_mgr = rust_frp_plugin::PluginManager::new();
            match plugin_mgr.create_plugin(pconf) {
                Ok(mut plugin) => {
                    if let Err(e) = plugin.handle(Box::new(visitor_conn)).await {
                        log::error!(
                            "Plugin handle error for proxy {}: {:?}",
                            proxy_name_clone,
                            e
                        );
                    }
                }
                Err(e) => {
                    log::error!(
                        "Failed to create plugin for proxy {}: {:?}",
                        proxy_name_clone,
                        e
                    );
                }
            }
            return;
        }

        log::debug!("使用工作连接协议处理: proxy={}", target_name);

        // 1. 查找代理对应的 run_id
        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&target_name).cloned()
        };

        log::debug!(
            "查找代理所有者: proxy={}, found={}",
            target_name,
            run_id.is_some()
        );

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for proxy: {}", target_name);
                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client");
                return;
            }
        };

        log::debug!("找到代理所有者: proxy={}, run_id={}", target_name, run_id);

        // 2. 获取对应的消息通道
        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found");
                return;
            }
        };

        log::debug!("找到消息通道: proxy={}, run_id={}", target_name, run_id);

        // 3. 从池中获取工作连接（池为空时会自动请求）
        match work_conn_manager
            .get_work_conn(&target_name, &msg_tx, Duration::from_secs(30), visitor_addr)
            .await
        {
            Ok(work_conn) => {
                log::info!(
                    "Got work conn for proxy {}, bridging with visitor",
                    target_name
                );
                match rust_frp_util::bridge_streams_counted(visitor_conn, work_conn).await {
                    Ok((to_work, to_visitor)) => {
                        // 流量统计：入方向 = 访问者→工作连接，出方向 = 工作连接→访问者
                        global_metrics().record_traffic(&target_name, to_work, to_visitor);
                    }
                    Err(e) => log::error!("Bridge error for proxy {}: {:?}", target_name, e),
                }
            }
            Err(e) => {
                log::error!("Failed to get work conn for {}: {}", target_name, e);
                let _ = visitor_conn.try_write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n");
            }
        }
    }

    /// 处理单个 WebSocket 访客连接：升级 + 工作连接桥接（由 accept 循环 spawn）
    async fn serve_websocket_visitor(
        proxy_name_clone: String,
        visitor_conn: tokio::net::TcpStream,
        visitor_addr: SocketAddr,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    ) {
        // per-proxy 连接统计守卫（drop 时自动减一）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&proxy_name_clone)
            .map(ProxyConnGuard::acquire);

        // 服务端插件回调：NewUserConn（可拒绝本次外部接入）
        if let Err(reason) = notify_new_user_conn(
            &plugin_manager,
            &control_manager,
            &proxy_owners,
            proxy_name_clone.as_str(),
            "websocket",
            &visitor_addr.to_string(),
        )
        .await
        {
            log::warn!(
                "WebSocket user conn from {} for proxy [{}] rejected by http plugin: {}",
                visitor_addr,
                proxy_name_clone,
                reason
            );
            return;
        }
        let ws_stream = match accept_async(visitor_conn).await {
            Ok(ws) => ws,
            Err(e) => {
                log::error!(
                    "WebSocket upgrade failed for proxy {}: {:?}",
                    proxy_name_clone,
                    e
                );
                return;
            }
        };

        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&proxy_name_clone).cloned()
        };

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for proxy: {}", proxy_name_clone);
                return;
            }
        };

        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                return;
            }
        };

        // 从池中获取工作连接
        match work_conn_manager
            .get_work_conn(
                &proxy_name_clone,
                &msg_tx,
                Duration::from_secs(30),
                visitor_addr,
            )
            .await
        {
            Ok(work_conn) => {
                log::info!(
                    "Got work conn for WebSocket proxy {}, bridging",
                    proxy_name_clone
                );
                let ws_conn = WebSocketConn::new(ws_stream, visitor_addr);
                match rust_frp_util::bridge_streams_counted(ws_conn, work_conn).await {
                    Ok((to_work, to_visitor)) => {
                        global_metrics().record_traffic(&proxy_name_clone, to_work, to_visitor);
                    }
                    Err(e) => {
                        log::error!(
                            "WebSocket bridge error for proxy {}: {:?}",
                            proxy_name_clone,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to get work conn for {}: {}", proxy_name_clone, e);
            }
        }
    }

    pub async fn stop_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Stopping proxy: {}", name);

        // 从 HTTP 虚拟主机路由器中注销
        self.http_vhost_router.unregister_proxy(name).await;

        // 从 tcpmux 路由表中注销（非 tcpmux 代理为空操作）
        self.tcpmux_router.unregister(name).await;

        // 负载均衡分组：成员退出组
        // - 组内仍有成员：保留共享监听器（故障摘除，流量由剩余成员承接）
        // - 组已空：关闭共享监听器（键为组端口，非代理名）
        let group_port = {
            let proxies = self.proxies.read().await;
            proxies
                .get(name)
                .and_then(|c| c.group.as_ref().and(c.remote_port))
        };
        if let Some(port) = group_port {
            let remaining = self.group_registry.member_count(port).await;
            let empty = self.group_registry.leave(port, name).await;
            if !empty {
                log::info!(
                    "proxy [{}] left group on port {} ({} remaining members, keeping shared listener)",
                    name,
                    port,
                    remaining.saturating_sub(1)
                );
                return Ok(());
            }
            let key = group_listener_key(port);
            let mut accept_handles = self.accept_handles.write().await;
            if let Some(handle) = accept_handles.remove(&key) {
                handle.abort();
                // 等待任务实际退出，确保监听 socket 释放后再返回
                //（否则新代理立刻重绑同端口会 AddrInUse）
                let _ = handle.await;
                log::info!("aborted group accept task for port {}", port);
            }
            let mut listeners = self.listeners.write().await;
            if let Some((_, running)) = listeners.remove(&key) {
                running.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            log::info!("group on port {} is empty, stopped shared listener", port);
            return Ok(());
        }

        // 中止 accept 任务，立即释放端口
        let mut accept_handles = self.accept_handles.write().await;
        if let Some(handle) = accept_handles.remove(name) {
            handle.abort();
            // 等待任务实际退出，确保监听 socket 释放（防重绑 AddrInUse 竞态）
            let _ = handle.await;
            log::info!("aborted accept task for proxy: {}", name);
        }

        // 停止 TCP 监听器（清理残留状态）
        let mut listeners = self.listeners.write().await;
        if let Some((_, running)) = listeners.remove(name) {
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            log::info!("stopped TCP proxy: {}", name);
        }

        // 停止 UDP 会话
        let mut udp_sessions = self.udp_sessions.write().await;
        if let Some(session) = udp_sessions.remove(name) {
            session
                .running
                .store(false, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            log::info!("stopped UDP proxy: {}", name);
        }
        Ok(())
    }

    /// 释放代理占用的用户端口配额（幂等，未记录时为空操作）
    async fn release_user_quota(&self, proxy_name: &str) {
        let entry = self.proxy_user_ports.write().await.remove(proxy_name);
        if let Some((user, ports_used)) = entry {
            let mut counts = self.user_port_counts.write().await;
            if let Some(current) = counts.get_mut(&user) {
                *current = current.saturating_sub(ports_used);
                if *current == 0 {
                    counts.remove(&user);
                }
            }
        }
    }

    /// 添加代理的统一入口
    ///
    /// - `user: Some(user)` 时执行 max_ports_per_user 配额检查与记账
    /// - 启动失败时回滚 proxies map 与配额预占，修复失败后残留条目的问题
    async fn add_proxy_inner(
        &self,
        config: &rust_frp_config::ProxyConfig,
        user: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. 同名代理冲突检查（与 frp 行为一致，防止覆盖导致旧监听器泄漏）
        {
            let proxies = self.proxies.read().await;
            if proxies.contains_key(&config.name) {
                return Err(format!("proxy [{}] already exists", config.name).into());
            }
        }

        // 1.5 负载均衡分组校验：仅 TCP、与插件互斥、必须指定 remote_port
        if let Some(ref group) = config.group {
            if config.r#type != "tcp" {
                return Err(format!(
                    "proxy [{}] rejected: group is only supported for tcp proxies",
                    config.name
                )
                .into());
            }
            if config.plugin.is_some() {
                return Err(format!(
                    "proxy [{}] rejected: group and plugin cannot be used together",
                    config.name
                )
                .into());
            }
            if config.remote_port.is_none() {
                return Err(format!(
                    "proxy [{}] rejected: group [{}] requires remote_port",
                    config.name, group
                )
                .into());
            }
        }

        // 2. 用户端口配额检查与预占（TCP/UDP 各占 1 个端口，其他类型不占用，与 frp 一致）
        let ports_used: usize = match config.r#type.as_str() {
            "tcp" | "udp" => 1,
            _ => 0,
        };
        if ports_used > 0 {
            if let (Some(user), Some(limit)) = (user, self.max_ports_per_user) {
                let mut counts = self.user_port_counts.write().await;
                let current = counts.get(user).copied().unwrap_or(0);
                if current + ports_used > limit {
                    return Err(format!(
                        "proxy [{}] rejected: user [{}] exceeds max_ports_per_user limit {}",
                        config.name, user, limit
                    )
                    .into());
                }
                counts.insert(user.to_string(), current + ports_used);
                drop(counts);
                self.proxy_user_ports
                    .write()
                    .await
                    .insert(config.name.clone(), (user.to_string(), ports_used));
            }
        }

        // 3. 先写入 map 声明代理名，启动失败则回滚
        {
            let mut proxies = self.proxies.write().await;
            proxies.insert(config.name.clone(), config.clone());
        }
        if let Err(e) = self.start_proxy(config).await {
            let mut proxies = self.proxies.write().await;
            proxies.remove(&config.name);
            if ports_used > 0 && self.max_ports_per_user.is_some() {
                self.release_user_quota(&config.name).await;
            }
            log::error!(
                "failed to start proxy [{}], rolled back: {:?}",
                config.name,
                e
            );
            return Err(e);
        }
        Ok(())
    }

    /// 发送 UDP 数据包到指定访问者
    pub async fn send_udp_packet(
        &self,
        proxy_name: &str,
        data: &[u8],
        client_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp_sessions = self.udp_sessions.read().await;
        if let Some(session) = udp_sessions.get(proxy_name) {
            let addr: SocketAddr = client_addr.parse()?;
            session.socket.send_to(data, &addr).await?;
            Ok(())
        } else {
            Err(format!("UDP proxy session not found: {}", proxy_name).into())
        }
    }

    pub fn get_http_vhost_router(&self) -> Arc<HttpVhostRouter> {
        self.http_vhost_router.clone()
    }

    /// tcpmux 路由表（供服务端复用器共享）
    pub fn get_tcpmux_router(&self) -> Arc<TcpMuxRouter> {
        self.tcpmux_router.clone()
    }
}

#[async_trait::async_trait]
impl ProxyManager for ServerProxyManager {
    async fn add_proxy(
        &self,
        config: rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.add_proxy_inner(&config, None).await
    }

    async fn add_proxy_for_user(
        &self,
        config: rust_frp_config::ProxyConfig,
        user: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.add_proxy_inner(&config, Some(user)).await
    }

    async fn remove_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop_proxy(name).await?;
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
        // 释放该代理占用的用户端口配额
        self.release_user_quota(name).await;
        Ok(())
    }

    async fn get_proxy_status(
        &self,
        name: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let proxies = self.proxies.read().await;
        if proxies.contains_key(name) {
            Ok(Some("running".to_string()))
        } else {
            Ok(None)
        }
    }

    async fn clear(&self) {
        let mut proxies = self.proxies.write().await;
        proxies.clear();
        self.user_port_counts.write().await.clear();
        self.proxy_user_ports.write().await.clear();
        log::info!("Server proxy manager cleared");
    }

    async fn send_udp_packet(
        &self,
        proxy_name: &str,
        data: &[u8],
        client_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp_sessions = self.udp_sessions.read().await;
        if let Some(session) = udp_sessions.get(proxy_name) {
            let addr: SocketAddr = client_addr.parse()?;
            session.socket.send_to(data, &addr).await?;
            Ok(())
        } else {
            Err(format!("UDP proxy session not found: {}", proxy_name).into())
        }
    }
}
