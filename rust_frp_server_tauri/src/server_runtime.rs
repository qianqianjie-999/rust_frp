//! 服务端后台运行时
//!
//! 独立线程跑 tokio runtime，进程内直接运行 `rust_frp_server::Server`
//! （与 CLI 版 rust_frps 同一条路径）。与前端通过通道 + Tauri 命令通信：
//!
//! - `cmd_rx`（前端 → runtime）：Start / Stop / Reload / Shutdown
//! - `status_tx`（runtime → 前端）：运行状态 + 在线客户端列表
//!
//! 状态来源：服务端 Dashboard 的 `/healthz`（免认证）与 `/api/clients`。
//! 停止方式：`Server::shutdown_handle()` 的 Notify 唤醒全部 accept 循环，
//! `start()` 返回后整体拆除会话 runtime，释放全部监听端口。

use rust_frp_config::ConfigLoader;
use rust_frp_server::Server;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 轮询 Dashboard 的间隔
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 运行状态（驱动托盘图标颜色与状态文案）
#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    /// 未启动 / 已停止
    Stopped,
    /// 启动中（进程内服务端已拉起，监听尚未就绪）
    Starting,
    /// 运行中（Dashboard /healthz 正常应答）
    Running,
    /// 出错（配置错误 / 端口被占 / 异常退出等）
    Error(String),
}

impl ConnState {
    /// 托盘 tooltip / 状态栏文案
    pub fn text(&self) -> String {
        match self {
            ConnState::Stopped => "已停止".to_string(),
            ConnState::Starting => "启动中".to_string(),
            ConnState::Running => "运行中".to_string(),
            ConnState::Error(e) => format!("错误: {e}"),
        }
    }
}

/// runtime → 前端的状态推送
pub struct StatusUpdate {
    pub state: ConnState,
    /// 在线客户端标识（Dashboard /api/clients；需要认证时为空）
    pub clients: Vec<String>,
    /// 附加说明（错误详情等）
    pub message: String,
}

/// 前端 → runtime 的命令
pub enum RuntimeCmd {
    Start,
    Stop,
    Reload,
    Shutdown,
}

/// GUI 直接掌控的「运行中服务端」控制柄
///
/// 会话任务创建 Server 后把 shutdown 句柄与 reload 通道存进来，
/// 供 Stop（优雅停机）与 Reload（热重载）命令使用。
#[derive(Default)]
pub struct Control {
    pub shutdown: Mutex<Option<Arc<tokio::sync::Notify>>>,
    pub reload_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

impl Control {
    fn clear(&self) {
        *self.shutdown.lock().unwrap() = None;
        *self.reload_tx.lock().unwrap() = None;
    }
}

/// 前端持有的 runtime 句柄
pub struct RuntimeHandle {
    pub cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>,
    pub status_rx: Receiver<StatusUpdate>,
    pub control: Arc<Control>,
}

/// 服务端是否应处于运行状态（供轮询任务区分「启动中」与「已停止」）
static SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// 会话代号：每次 Start 自增。会话任务在关键节点核对代号，
/// 防止「Stop 后旧会话才完成初始化」把服务端又拉起来。
static SESSION_GEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 轮询线程停止标志（std::thread 无法 abort，用标志位优雅退出）
static POLL_STOP: AtomicBool = AtomicBool::new(false);

/// 启动后台 runtime 线程（立即返回，不阻塞前端）
pub fn spawn_runtime(config_path: PathBuf, web_port: u16) -> RuntimeHandle {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<RuntimeCmd>();
    let (status_tx, status_rx) = std::sync::mpsc::channel::<StatusUpdate>();
    let control: Arc<Control> = Arc::new(Control::default());

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Error(format!("tokio runtime 创建失败: {e}")),
                    clients: Vec::new(),
                    message: String::new(),
                });
                return;
            }
        };
        rt.block_on(runtime_loop(
            config_path,
            web_port,
            cmd_rx,
            status_tx,
            control.clone(),
        ));
    });

    RuntimeHandle {
        cmd_tx,
        status_rx,
        control,
    }
}

/// 轮询线程停止标志（供 Shutdown 命令置位）
fn stop_poller() {
    POLL_STOP.store(true, Ordering::SeqCst);
}

async fn runtime_loop(
    config_path: PathBuf,
    web_port: u16,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<RuntimeCmd>,
    status_tx: Sender<StatusUpdate>,
    control: Arc<Control>,
) {
    let mut session_rt: Option<tokio::runtime::Runtime> = None;

    // 状态轮询线程：常驻。刻意用独立 OS 线程 + 阻塞 I/O（裸 std::net），
    // 与 tokio runtime 完全隔离，避免拖饿会话 runtime 上的 axum Dashboard。
    let poll_tx = status_tx.clone();
    let poll_port = web_port;
    let _poller = std::thread::Builder::new()
        .name("frps-gui-status-poll".into())
        .spawn(move || {
            let mut last: Option<ConnState> = None;
            while !POLL_STOP.load(Ordering::SeqCst) {
                std::thread::sleep(POLL_INTERVAL);
                let update = poll_status(poll_port);
                if last.as_ref() != Some(&update.state) {
                    last = Some(update.state.clone());
                    log::info!(
                        "状态轮询: {:?} (clients={:?}) -> 推送前端",
                        update.state,
                        update.clients
                    );
                    let _ = poll_tx.send(update);
                }
            }
            log::info!("状态轮询线程已退出");
        })
        .expect("状态轮询线程创建失败");

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            RuntimeCmd::Start => {
                // 任何状态下都先整体拆除上一次会话（释放全部监听端口），再拉新会话
                teardown(&mut session_rt, &control).await;
                SERVER_RUNNING.store(true, Ordering::SeqCst);
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Starting,
                    clients: Vec::new(),
                    message: "正在启动服务端…".to_string(),
                });

                let path = config_path.clone();
                let tx = status_tx.clone();
                let ctrl = control.clone();
                let gen = SESSION_GEN.fetch_add(1, Ordering::SeqCst) + 1;
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(4)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        SERVER_RUNNING.store(false, Ordering::SeqCst);
                        let _ = tx.send(StatusUpdate {
                            state: ConnState::Error(format!("服务端运行时创建失败: {e}")),
                            clients: Vec::new(),
                            message: format!("服务端运行时创建失败: {e}"),
                        });
                        continue;
                    }
                };
                rt.spawn(session_task(path, tx, ctrl, gen));
                session_rt = Some(rt);
            }
            RuntimeCmd::Stop => {
                SERVER_RUNNING.store(false, Ordering::SeqCst);
                // 优雅停机：唤醒全部 accept 循环，start() 随之返回
                if let Some(handle) = control.shutdown.lock().unwrap().take() {
                    handle.notify_waiters();
                    handle.notify_one();
                }
                *control.reload_tx.lock().unwrap() = None;
                if let Some(rt) = session_rt.take() {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(500));
                        rt.shutdown_timeout(Duration::from_secs(3));
                    });
                }
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Stopped,
                    clients: Vec::new(),
                    message: "已停止".to_string(),
                });
            }
            RuntimeCmd::Reload => {
                if let Some(tx) = control.reload_tx.lock().unwrap().as_ref() {
                    let _ = tx.send(()).await;
                    log::info!("已发送热重载命令");
                } else {
                    log::warn!("服务端未在运行，忽略重载命令");
                }
            }
            RuntimeCmd::Shutdown => {
                SERVER_RUNNING.store(false, Ordering::SeqCst);
                if let Some(handle) = control.shutdown.lock().unwrap().take() {
                    handle.notify_waiters();
                    handle.notify_one();
                }
                *control.reload_tx.lock().unwrap() = None;
                if let Some(rt) = session_rt.take() {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(500));
                        rt.shutdown_timeout(Duration::from_secs(3));
                    });
                }
                // 轮询是独立 OS 线程，无法 abort：置停止标志，由其自行退出
                stop_poller();
                break;
            }
        }
    }
}

/// 整体拆除上一次服务端会话：先发优雅停机信号，再限时回收 runtime
async fn teardown(session_rt: &mut Option<tokio::runtime::Runtime>, control: &Arc<Control>) {
    if let Some(handle) = control.shutdown.lock().unwrap().take() {
        handle.notify_waiters();
        handle.notify_one();
    }
    *control.reload_tx.lock().unwrap() = None;
    if let Some(rt) = session_rt.take() {
        log::warn!("拆除上一次服务端会话（释放监听端口）");
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            rt.shutdown_timeout(Duration::from_secs(3));
        });
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
}

/// 单个服务端会话：进程内运行 rust_frp_server::Server 直到退出。
///
/// `gen` 为本会话代号：关键节点（拿到 Server 后、启动前）与收尾时核对，
/// 代号已过期（期间发生了新的 Start）则静默放弃，不覆盖新会话的状态。
async fn session_task(
    config_path: PathBuf,
    status_tx: Sender<StatusUpdate>,
    control: Arc<Control>,
    gen: usize,
) {
    let stale = |msg: &str| {
        log::info!("会话 #{gen} 已过期，放弃: {msg}");
    };
    let path_str = config_path.to_string_lossy().to_string();
    let config = match ConfigLoader::load_server_config_strict(&path_str, true) {
        Ok(c) => c,
        Err(e) => {
            SERVER_RUNNING.store(false, Ordering::SeqCst);
            let msg = format!("配置加载失败: {e}");
            let _ = status_tx.send(StatusUpdate {
                state: ConnState::Error(msg.clone()),
                clients: Vec::new(),
                message: msg,
            });
            return;
        }
    };
    if SESSION_GEN.load(Ordering::SeqCst) != gen {
        stale("配置加载完成时代号已过期");
        return;
    }
    log::info!(
        "GUI 启动服务端: bind={}:{}, dashboard={}:{}, vhost_http={:?}",
        config.bind_addr,
        config.bind_port,
        config.web_server.addr,
        config.web_server.port
    );
    let mut server = match Server::new(config, Some(path_str.clone())).await {
        Ok(s) => s,
        Err(e) => {
            SERVER_RUNNING.store(false, Ordering::SeqCst);
            let msg = format!("服务端初始化失败: {e}（监听端口被占用？）");
            let _ = status_tx.send(StatusUpdate {
                state: ConnState::Error(msg.clone()),
                clients: Vec::new(),
                message: msg,
            });
            return;
        }
    };
    if SESSION_GEN.load(Ordering::SeqCst) != gen {
        stale("Server 创建完成时代号已过期");
        return;
    }

    // 停机句柄与热重载通道交给 GUI 掌控（对齐 CLI 版 rust_frps 的装配方式）
    let shutdown = server.shutdown_handle();
    *control.shutdown.lock().unwrap() = Some(shutdown);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<()>(16);
    server.set_reload_rx(reload_rx);
    server.set_reload_tx(reload_tx.clone());
    *control.reload_tx.lock().unwrap() = Some(reload_tx.clone());

    // 配置文件监听（对齐 CLI 版：防抖 500ms 触发热重载）
    spawn_config_watcher(&path_str, reload_tx).await;

    match server.start().await {
        Ok(()) => {
            SERVER_RUNNING.store(false, Ordering::SeqCst);
            if SESSION_GEN.load(Ordering::SeqCst) == gen {
                control.clear();
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Stopped,
                    clients: Vec::new(),
                    message: "服务端已退出".to_string(),
                });
            }
        }
        Err(e) => {
            SERVER_RUNNING.store(false, Ordering::SeqCst);
            if SESSION_GEN.load(Ordering::SeqCst) == gen {
                control.clear();
                let msg = format!("服务端异常退出: {e}");
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Error(msg.clone()),
                    clients: Vec::new(),
                    message: msg,
                });
            }
        }
    }
}

/// 监听配置文件变更 → 触发热重载（对齐 CLI 版 rust_frps）
async fn spawn_config_watcher(path_str: &str, reload_tx: tokio::sync::mpsc::Sender<()>) {
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
                log::warn!("创建配置文件监听失败: {e}");
                return;
            }
        };
    if let Err(e) = watcher.watch(std::path::Path::new(path_str), RecursiveMode::NonRecursive) {
        log::warn!("监听配置文件 {path_str} 失败: {e}");
        return;
    }
    log::info!("配置文件监听已启动: {path_str}");
    tokio::spawn(async move {
        let _keep = watcher; // 保活：watcher 被 drop 即停止监听
        loop {
            if watch_rx.recv().await.is_none() {
                break;
            }
            // 防抖：等待文件写入完成
            tokio::time::sleep(Duration::from_millis(500)).await;
            if reload_tx.send(()).await.is_err() {
                break;
            }
        }
    });
}

/// 轮询 Dashboard 推断运行状态
fn poll_status(web_port: u16) -> StatusUpdate {
    if !SERVER_RUNNING.load(Ordering::SeqCst) {
        return StatusUpdate {
            state: ConnState::Stopped,
            clients: Vec::new(),
            message: String::new(),
        };
    }
    if web_port == 0 {
        return StatusUpdate {
            state: ConnState::Running,
            clients: Vec::new(),
            message: "未启用 Dashboard，仅显示进程内状态".to_string(),
        };
    }
    if http_get_ok(web_port, "/healthz") {
        let clients = fetch_clients(web_port);
        let msg = if clients.is_empty() {
            "运行中（无在线客户端，或 Dashboard 已设密码无法读取列表）".to_string()
        } else {
            format!("运行中，{} 个客户端在线", clients.len())
        };
        StatusUpdate {
            state: ConnState::Running,
            clients,
            message: msg,
        }
    } else {
        StatusUpdate {
            state: ConnState::Starting,
            clients: Vec::new(),
            message: "Dashboard 未响应（启动中或端口未开放）".to_string(),
        }
    }
}

/// 从 /api/clients 拉取在线客户端标识（需要 Dashboard 认证时静默放弃）
fn fetch_clients(port: u16) -> Vec<String> {
    let Some(v) = http_get_json(port, "/api/clients") else {
        return Vec::new();
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => {
            // 兼容 {"clients": [...]} 包装
            v.get("clients").and_then(|c| c.as_array()).cloned().unwrap_or_default()
        }
    };
    arr.iter()
        .filter_map(|item| {
            item.get("client_id")
                .or_else(|| item.get("id"))
                .or_else(|| item.get("user"))
                .and_then(|x| x.as_str())
                .map(String::from)
        })
        .collect()
}

/// 裸 HTTP GET，仅判断是否 200
pub fn http_get_ok(port: u16, path: &str) -> bool {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(800))
    else {
        return false;
    };
    if stream.set_read_timeout(Some(Duration::from_secs(2))).is_err()
        || stream.set_write_timeout(Some(Duration::from_secs(2))).is_err()
    {
        return false;
    }
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut resp = String::new();
    if stream.read_to_string(&mut resp).is_err() {
        return false;
    }
    resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200")
}

/// 裸 HTTP GET 取 JSON（无 reqwest 依赖；Dashboard 固定本机访问）
pub fn http_get_json(port: u16, path: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok()?;
    let (_head, body) = resp.split_once("\r\n\r\n")?;
    serde_json::from_str(body).ok()
}
