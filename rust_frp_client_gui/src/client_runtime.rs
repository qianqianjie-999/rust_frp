//! 客户端后台运行时
//!
//! 独立线程跑 tokio runtime，进程内直接运行 `rust_frp_client::Client`
//! （不再是拉起命令行子进程）。与 GUI 线程通过两个通道通信：
//!
//! - `cmd_rx`（GUI → runtime）：Start / Stop / Shutdown
//! - `status_tx`（runtime → GUI）：连接状态 + 访问者列表
//!
//! 状态来源：客户端内置管理端口 `GET /status`（对齐 `frpc status` 子命令）。
//! 该端点在 `web_server.port > 0` 时由 Client 自动启动，返回已注册的
//! 代理/访问者列表——**访问者非空即登录成功**，正是托盘指示灯所需的信号。

use rust_frp_client::Client;
use rust_frp_config::ConfigLoader;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

/// 轮询管理端口的间隔
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 连接状态（驱动托盘图标颜色与状态文案）
#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    /// 未启动 / 已停止
    Stopped,
    /// 启动中（进程内客户端已拉起，尚未登录成功）
    Starting,
    /// 已连接（登录成功且访问者已注册）
    Connected,
    /// 连接中 / 重连中（管理端口可达但访问者未就绪）
    Reconnecting,
    /// 出错（配置错误 / 客户端异常退出等）
    Error(String),
}

impl ConnState {
    /// 托盘 tooltip / 状态栏文案
    pub fn text(&self) -> String {
        match self {
            ConnState::Stopped => "已停止".to_string(),
            ConnState::Starting => "启动中".to_string(),
            ConnState::Connected => "已连接".to_string(),
            ConnState::Reconnecting => "连接中/重连中".to_string(),
            ConnState::Error(e) => format!("错误: {e}"),
        }
    }
}

/// runtime → GUI 的状态推送
pub struct StatusUpdate {
    pub state: ConnState,
    /// 已注册的访问者名称（登录成功的直接证据）
    pub visitors: Vec<String>,
    /// 附加说明（错误详情等）
    pub message: String,
}

/// GUI → runtime 的命令
pub enum RuntimeCmd {
    Start,
    Stop,
    Shutdown,
}

/// GUI 持有的 runtime 句柄
pub struct RuntimeHandle {
    pub cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>,
    pub status_rx: Receiver<StatusUpdate>,
}

/// 启动后台 runtime 线程（立即返回，不阻塞 GUI）
pub fn spawn_runtime(config_path: PathBuf, web_port: u16) -> RuntimeHandle {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<RuntimeCmd>();
    let (status_tx, status_rx) = std::sync::mpsc::channel::<StatusUpdate>();

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
                    visitors: Vec::new(),
                    message: String::new(),
                });
                return;
            }
        };
        rt.block_on(runtime_loop(config_path, web_port, cmd_rx, status_tx));
    });

    RuntimeHandle { cmd_tx, status_rx }
}

/// 客户端是否应处于运行状态（供轮询任务区分「启动中」与「已停止」）
static CLIENT_RUNNING: AtomicBool = AtomicBool::new(false);

/// 轮询线程停止标志（std::thread 无法 abort，用标志位优雅退出）
static POLL_STOP: AtomicBool = AtomicBool::new(false);

async fn runtime_loop(
    config_path: PathBuf,
    web_port: u16,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<RuntimeCmd>,
    status_tx: Sender<StatusUpdate>,
) {
    let mut client_task: Option<tokio::task::JoinHandle<()>> = None;

    // 状态轮询线程：常驻，按 CLIENT_RUNNING 解释「管理端口连不上」的含义。
    //
    // 刻意用独立 OS 线程 + 阻塞 I/O，与 tokio runtime 完全隔离：轮询走裸
    // std::net 阻塞读写，若作为 task 跑在 runtime worker 上，一次 /status
    // 轮询会把 worker 占住数秒，同一 runtime 上的 axum 管理服务随之被拖饿——
    // 实测轮询任务自身请求 100% read 超时（自己饿死自己：请求写进 backlog
    // 后自己占住唯一可用的 worker，服务端要等它的 read 超时才排得上程），
    // 外部 curl 也被延迟 ~1.5s。独立线程与调度器再无瓜葛。
    let poll_tx = status_tx.clone();
    let poll_port = web_port;
    let _poller = std::thread::Builder::new()
        .name("frpc-gui-status-poll".into())
        .spawn(move || {
            let mut last: Option<ConnState> = None;
            while !POLL_STOP.load(Ordering::SeqCst) {
                std::thread::sleep(POLL_INTERVAL);
                let running = CLIENT_RUNNING.load(Ordering::SeqCst);
                let mut update = poll_status(poll_port);
                if !running {
                    update.state = ConnState::Stopped;
                    update.visitors.clear();
                    update.message.clear();
                }
                if last.as_ref() != Some(&update.state) {
                    last = Some(update.state.clone());
                    log::info!(
                        "状态轮询: {:?} (visitors={:?}) -> 推送 GUI",
                        update.state,
                        update.visitors
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
                if client_task.is_some() {
                    continue;
                }
                CLIENT_RUNNING.store(true, Ordering::SeqCst);
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Starting,
                    visitors: Vec::new(),
                    message: "正在启动客户端…".to_string(),
                });

                let path = config_path.clone();
                let tx = status_tx.clone();
                client_task = Some(tokio::spawn(async move {
                    let path_str = path.to_string_lossy().to_string();
                    // 同步读小配置文件，可接受（异步块内的短阻塞）
                    let config = match ConfigLoader::load_client_config_strict(&path_str, true) {
                        Ok(c) => c,
                        Err(e) => {
                            CLIENT_RUNNING.store(false, Ordering::SeqCst);
                            let _ = tx.send(StatusUpdate {
                                state: ConnState::Error(format!("配置加载失败: {e}")),
                                visitors: Vec::new(),
                                message: format!("配置加载失败: {e}"),
                            });
                            return;
                        }
                    };
                    log::info!(
                        "GUI 启动客户端: server={}:{}, visitors={}",
                        config.server_addr,
                        config.server_port,
                        config.visitors.len()
                    );
                    let mut client = match Client::new(config, Some(path_str)) {
                        Ok(c) => c,
                        Err(e) => {
                            CLIENT_RUNNING.store(false, Ordering::SeqCst);
                            let _ = tx.send(StatusUpdate {
                                state: ConnState::Error(format!("客户端初始化失败: {e}")),
                                visitors: Vec::new(),
                                message: format!("客户端初始化失败: {e}"),
                            });
                            return;
                        }
                    };
                    match client.start().await {
                        Ok(()) => {
                            CLIENT_RUNNING.store(false, Ordering::SeqCst);
                            let _ = tx.send(StatusUpdate {
                                state: ConnState::Stopped,
                                visitors: Vec::new(),
                                message: "客户端已退出".to_string(),
                            });
                        }
                        Err(e) => {
                            CLIENT_RUNNING.store(false, Ordering::SeqCst);
                            let _ = tx.send(StatusUpdate {
                                state: ConnState::Error(format!("客户端异常退出: {e}")),
                                visitors: Vec::new(),
                                message: format!("客户端异常退出: {e}"),
                            });
                        }
                    }
                }));
            }
            RuntimeCmd::Stop => {
                CLIENT_RUNNING.store(false, Ordering::SeqCst);
                if let Some(handle) = client_task.take() {
                    stop_client(web_port, handle).await;
                }
                let _ = status_tx.send(StatusUpdate {
                    state: ConnState::Stopped,
                    visitors: Vec::new(),
                    message: "已停止".to_string(),
                });
            }
            RuntimeCmd::Shutdown => {
                CLIENT_RUNNING.store(false, Ordering::SeqCst);
                if let Some(handle) = client_task.take() {
                    stop_client(web_port, handle).await;
                }
                // 轮询是独立 OS 线程，无法 abort：置停止标志，由其自行退出
                POLL_STOP.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}

/// 停止客户端：先走管理端口优雅退出（排空存量连接），超时未退则强杀任务
async fn stop_client(web_port: u16, handle: tokio::task::JoinHandle<()>) {
    if web_port > 0 {
        // 阻塞 HTTP 放 blocking 池执行，避免占住 async worker（同轮询器饿死原理）
        let port = web_port;
        let _ = tokio::task::spawn_blocking(move || http_post(port, "/stop")).await;
    }
    // 给优雅退出留时间（向服务端发 Disconnect + 排空连接）
    for _ in 0..10 {
        if handle.is_finished() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    handle.abort();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// 轮询管理端口 `/status`，推断连接状态
fn poll_status(port: u16) -> StatusUpdate {
    if port == 0 {
        return StatusUpdate {
            state: ConnState::Error("未配置管理端口，无法获取状态".to_string()),
            visitors: Vec::new(),
            message: "请在高级选项中设置管理端口".to_string(),
        };
    }
    match http_get_json(port, "/status") {
        Some(v) => {
            let visitors: Vec<String> = v
                .get("visitors")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            item.get("name")
                                .and_then(|n| n.as_str())
                                .map(String::from)
                        })
                        .collect()
                })
                .unwrap_or_default();
            if visitors.is_empty() {
                StatusUpdate {
                    state: ConnState::Reconnecting,
                    visitors,
                    message: "管理端口已就绪，等待登录/访问者注册…".to_string(),
                }
            } else {
                StatusUpdate {
                    state: ConnState::Connected,
                    visitors: visitors.clone(),
                    message: format!("已连接，{} 个访问者已注册", visitors.len()),
                }
            }
        }
        None => StatusUpdate {
            state: ConnState::Reconnecting,
            visitors: Vec::new(),
            message: "管理端口无响应（启动中或已停止）".to_string(),
        },
    }
}

/// 裸 HTTP GET（无 reqwest 依赖；管理端口固定监听 127.0.0.1，无认证）
///
/// 分步返回 None 并记日志：本地回环服务出问题时能定位到具体步骤。
pub fn http_get_json(port: u16, path: &str) -> Option<serde_json::Value> {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("http_get_json: connect {addr} 失败: {e}");
            return None;
        }
    };
    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(2))) {
        log::warn!("http_get_json: set_read_timeout 失败: {e}");
        return None;
    }
    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(2))) {
        log::warn!("http_get_json: set_write_timeout 失败: {e}");
        return None;
    }
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    if let Err(e) = stream.write_all(request.as_bytes()) {
        log::warn!("http_get_json: write 失败: {e}");
        return None;
    }
    let mut resp = String::new();
    if let Err(e) = stream.read_to_string(&mut resp) {
        log::warn!(
            "http_get_json: read 失败: {e}（已读 {} 字节）",
            resp.len()
        );
        return None;
    }
    let Some((_head, body)) = resp.split_once("\r\n\r\n") else {
        log::warn!(
            "http_get_json: 响应无 CRLFCRLF（{} 字节）: {:?}",
            resp.len(),
            &resp[..resp.len().min(100)]
        );
        return None;
    };
    match serde_json::from_str(body) {
        Ok(v) => Some(v),
        Err(e) => {
            log::warn!("http_get_json: JSON 解析失败: {e}");
            None
        }
    }
}

/// 裸 HTTP POST（用于 /reload、/stop）
pub fn http_post(port: u16, path: &str) -> bool {
    use std::io::{Read, Write};
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return false;
    }
    if write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let mut resp = String::new();
    stream.read_to_string(&mut resp).is_ok() && resp.contains("200")
}
