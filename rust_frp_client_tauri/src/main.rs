//! rust_frp 客户端 Tauri 图形界面
//!
//! 成熟方案（对比此前 egui 在 Windows 上「收托盘→再显示」反复出问题）：
//! Tauri 2 的托盘显隐/聚焦是官方成熟 API，彻底根治隐藏窗口恢复不可靠的顽疾。
//!
//! 架构：
//! - `client_runtime` 在独立 tokio runtime 进程内运行 `rust_frp_client::Client`，
//!   通过 `cmd_tx`（Start/Stop/Shutdown）与 `status_rx`（连接状态）通信。
//! - 状态线程独占 `status_rx`，把最新状态写入共享 `latest` 并刷新托盘图标/tooltip。
//! - 前端（网页控制台）通过 Tauri 命令读写配置、启停、拉状态。
//! - 窗口关闭 → 取消关闭并隐藏到托盘；托盘「显示主窗口」/左键单击 → 显示并聚焦。

// 本二进制是 GUI 程序：设为 Windows 子系统，避免启动时报一个黑控制台窗口。
// 仅影响本 crate 的编译产物，不影响其它 CLI 工具（rust_frpc 等）。
#![windows_subsystem = "windows"]

mod autostart;
mod client_runtime;
mod config_ui;
mod icon;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_runtime::{ConnState, RuntimeCmd};
use config_ui::ClientConfigUi;
use rust_frp_util::init_logging;
use serde::Deserialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::{Builder, Manager, WindowEvent};

/// 共享的最新连接状态（状态线程写、get_status 命令读）
struct LatestStatus {
    state: ConnState,
    visitors: Vec<String>,
    message: String,
}

/// Tauri 托管的全局状态
struct AppState {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>,
    latest: Arc<Mutex<LatestStatus>>,
    config_path: PathBuf,
}

/// 前端 get_status 的返回结构
#[derive(serde::Serialize)]
struct StatusResponse {
    state: String,
    text: String,
    visitors: Vec<String>,
    message: String,
}

/// set_autostart 入参
#[derive(Deserialize)]
struct SetAutostartPayload {
    enable: bool,
}

/// 计算配置文件路径：可执行文件同级目录下的 frpc-win.toml
fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("frpc-win.toml")
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

#[tauri::command]
fn start(state: tauri::State<AppState>) {
    let _ = state.cmd_tx.send(RuntimeCmd::Start);
}

#[tauri::command]
fn stop(state: tauri::State<AppState>) {
    let _ = state.cmd_tx.send(RuntimeCmd::Stop);
}

#[tauri::command]
fn get_status(state: tauri::State<AppState>) -> StatusResponse {
    let l = state.latest.lock().unwrap();
    StatusResponse {
        state: format!("{:?}", l.state),
        text: l.state.text(),
        visitors: l.visitors.clone(),
        message: l.message.clone(),
    }
}

#[tauri::command]
fn load_config(state: tauri::State<AppState>) -> Result<ClientConfigUi, String> {
    Ok(ClientConfigUi::load(&state.config_path))
}

#[tauri::command]
fn save_config(state: tauri::State<AppState>, cfg: ClientConfigUi) -> Result<(), String> {
    cfg.save(&state.config_path)?;
    // 运行中的客户端经文件监听自动热重载；主动补发 reload 双保险
    if let Ok(port) = cfg.web_port.trim().parse::<u16>() {
        if port > 0 {
            std::thread::spawn(move || {
                let _ = client_runtime::http_post(port, "/reload");
            });
        }
    }
    Ok(())
}

#[tauri::command]
fn get_autostart() -> bool {
    autostart::is_enabled()
}

#[tauri::command]
fn set_autostart(payload: SetAutostartPayload) -> Result<(), String> {
    autostart::set_enabled(payload.enable)
}

/// 单实例保护：用本地固定端口做互斥锁，保证全系统只有一个 GUI 实例在跑。
///
/// 为什么需要：开机时「Run 键自启」+「桌面环境就绪」可能双拉两个
/// `rust_frpc-gui.exe`，两个实例抢 9310（管理端口）与 9311（STCP visitor），
/// 一个 bind 失败就静默死掉，表现正是「STCP 联不上、点启动没反应」。
/// 第二个实例 bind 同一端口会得到 EADDRINUSE，直接退出，由先启动的那个继续服务。
///
/// 返回 Some(监听器) = 本实例可继续（调用方须持有它以保持端口占用）；
/// 返回 None = 已有实例在运行，调用方应退出。
fn ensure_single_instance() -> Option<std::net::TcpListener> {
    match std::net::TcpListener::bind("127.0.0.1:49171") {
        Ok(l) => Some(l),
        Err(e) => {
            log::info!("检测到已有 rust_frpc-gui 实例在运行（49171 被占: {e}），本实例退出");
            None
        }
    }
}

/// TCP 连通性探测（用于开机等待网络就绪）
fn tcp_reachable(addr: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (addr, port)
        .to_socket_addrs()
        .map(|i| i.collect())
        .unwrap_or_default();
    for sa in addrs {
        if std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(1000)).is_ok()
        {
            return true;
        }
    }
    false
}

/// 启动即连接，但开机时网络（WiFi/DNS）可能尚未就绪：先轮询服务端可达，
/// 成功或超时（30s）后再发 Start，避免首轮 login 在链路未起时失败而卡死。
/// 配置缺失则退化为固定延迟 3s。
fn spawn_auto_connect(cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>, cfg_path: PathBuf) {
    std::thread::spawn(move || {
        let mut server: Option<(String, u16)> = None;
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            if let Ok(tbl) = text.parse::<toml::Table>() {
                let addr = tbl.get("server_addr").and_then(|v| v.as_str());
                let port = tbl
                    .get("server_port")
                    .and_then(|v| v.as_integer())
                    .map(|p| p as u16);
                if let (Some(a), Some(p)) = (addr, port) {
                    server = Some((a.to_string(), p));
                }
            }
        }
        match server {
            Some((addr, port)) => {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                let mut ready = false;
                while std::time::Instant::now() < deadline {
                    if tcp_reachable(&addr, port) {
                        ready = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                if !ready {
                    log::warn!("等待服务端 {addr}:{port} 可达超时(30s)，仍尝试启动客户端");
                }
            }
            None => {
                log::warn!("未读到 server_addr/port，退化延迟 3s 后启动");
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }
        log::info!("网络就绪（或已超时），发送 Start 命令");
        let _ = cmd_tx.send(RuntimeCmd::Start);
    });
}

fn main() {
    // 单实例：第二个实例直接退出，避免双实例抢端口；
    // 返回 Some 时持有监听器，进程存活期间一直占用 49171，阻止第二个实例启动。
    let _instance_lock = match ensure_single_instance() {
        Some(l) => l,
        None => return,
    };

    // 文件日志（与旧版一致：写到 exe 同级 frpc-gui.log，保留 7 天）
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let log_file = exe_dir.join("frpc-gui.log");
    if let Err(e) = init_logging(log_file.to_str(), Some("info"), 7) {
        eprintln!("初始化日志失败: {e}");
    }
    // init_logging 装的是 tracing 订阅器，这里把 log 门面桥接到 tracing，
    // 否则本 crate 及复用模块里的 log::info!/log::warn! 全是静默空操作。
    let _ = tracing_log::LogTracer::init();
    log::info!(
        "rust_frpc-gui (tauri) 启动，工作目录: {}",
        exe_dir.display()
    );

    let cfg_path = config_path();
    log::info!("配置文件路径: {}", cfg_path.display());

    // 加载配置以取得管理端口（状态轮询用）；读不到则默认 9310
    let web_port: u16 = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|d| {
            d.get("web_server")
                .and_then(|w| w.get("port"))
                .and_then(|p| p.as_integer())
                .map(|p| p as u16)
        })
        .unwrap_or(9310);

    let runtime = client_runtime::spawn_runtime(cfg_path.clone(), web_port);
    let cmd_tx = runtime.cmd_tx.clone();
    let status_rx = runtime.status_rx;

    let latest = Arc::new(Mutex::new(LatestStatus {
        state: ConnState::Stopped,
        visitors: Vec::new(),
        message: "就绪".to_string(),
    }));

    // 启动即连接（托盘服务语义：打开就连，无需用户再点启动）。
    // 但开机网络可能未就绪，改为先等服务端可达再发 Start，避免首轮 login 失败卡死。
    spawn_auto_connect(cmd_tx.clone(), cfg_path.clone());

    let app_state = AppState {
        cmd_tx: cmd_tx.clone(),
        latest: latest.clone(),
        config_path: cfg_path,
    };

    let latest_for_thread = latest.clone();

    Builder::default()
        .setup(move |app| {
            // 主窗口关闭 → 取消关闭并隐藏到托盘（托盘「退出」才真正结束）
            if let Some(win) = app.get_webview_window("main") {
                let win2 = win.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = win2.hide();
                    }
                });
            }

            // 托盘菜单项
            let show_item =
                MenuItem::with_id(app.handle(), "show", "显示主窗口", true, None::<&str>)?;
            let start_item = MenuItem::with_id(app.handle(), "start", "启动", true, None::<&str>)?;
            let stop_item = MenuItem::with_id(app.handle(), "stop", "停止", true, None::<&str>)?;
            let reload_item =
                MenuItem::with_id(app.handle(), "reload", "重载配置", true, None::<&str>)?;
            let autostart_item =
                MenuItem::with_id(app.handle(), "autostart", "开机自启", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app.handle(), "quit", "退出", true, None::<&str>)?;

            let menu = Menu::new(app.handle())?;
            menu.append(&show_item)?;
            menu.append(&start_item)?;
            menu.append(&stop_item)?;
            menu.append(&reload_item)?;
            menu.append(&PredefinedMenuItem::separator(app.handle())?)?;
            menu.append(&autostart_item)?;
            menu.append(&PredefinedMenuItem::separator(app.handle())?)?;
            menu.append(&quit_item)?;

            let autostart_on = autostart::is_enabled();
            let _ = autostart_item.set_text(if autostart_on {
                "✓ 开机自启"
            } else {
                "开机自启"
            });

            // 事件回调捕获
            let tray_cmd = cmd_tx.clone();
            let tray_port = web_port;
            let tray_app = app.handle().clone();

            let tray = TrayIconBuilder::with_id("main")
                .icon(icon::status_image(&ConnState::Stopped))
                .tooltip("rust_frp 客户端")
                .show_menu_on_left_click(false)
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "start" => {
                        let _ = tray_cmd.send(RuntimeCmd::Start);
                    }
                    "stop" => {
                        let _ = tray_cmd.send(RuntimeCmd::Stop);
                    }
                    "reload" => {
                        if tray_port > 0 {
                            std::thread::spawn(move || {
                                let _ = client_runtime::http_post(tray_port, "/reload");
                            });
                        }
                    }
                    "autostart" => {
                        let next = !autostart::is_enabled();
                        if autostart::set_enabled(next).is_ok() {
                            let _ = autostart_item.set_text(if next {
                                "✓ 开机自启"
                            } else {
                                "开机自启"
                            });
                        }
                    }
                    "quit" => {
                        let qcmd = tray_cmd.clone();
                        let qapp = app.clone();
                        std::thread::spawn(move || {
                            let _ = qcmd.send(RuntimeCmd::Shutdown);
                            std::thread::sleep(Duration::from_millis(800));
                            qapp.exit(0);
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(move |_tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        ..
                    } = event
                    {
                        show_main_window(&tray_app);
                    }
                })
                .build(app.handle())?;

            // 状态线程：独占 status_rx，刷新共享状态 + 托盘图标
            let latest_t = latest_for_thread.clone();
            let tray_t = tray.clone();
            std::thread::spawn(move || {
                // 发送端丢弃（recv 返回 Err）即退出——等价于 while let 的终止条件
                while let Ok(u) = status_rx.recv() {
                    {
                        let mut l = latest_t.lock().unwrap();
                        l.state = u.state.clone();
                        l.visitors = u.visitors.clone();
                        l.message = u.message.clone();
                    }
                    let _ = tray_t.set_icon(Some(icon::status_image(&u.state)));
                    let _ = tray_t.set_tooltip(Some(format!("rust_frp - {}", u.state.text())));
                }
            });

            Ok(())
        })
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            start,
            stop,
            get_status,
            load_config,
            save_config,
            get_autostart,
            set_autostart
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
