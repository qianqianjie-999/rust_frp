//! rust_frp 服务端 Tauri 图形界面
//!
//! 与客户端 GUI（rust_frp_client_tauri）同架构：托盘 + 网页控制台，
//! 进程内直接运行 `rust_frp_server::Server`（与 CLI 版 rust_frps 同路径）。
//!
//! 差异点：
//! - 服务端只绑定本地端口，无需等网络就绪 → 启动即 Start
//! - 停止走 `Server::shutdown_handle()` 优雅排空，非强杀
//! - 状态来自 Dashboard `/healthz`（免认证）与 `/api/clients`
//! - 配置文件 frps-win.toml（exe 同级），保存后由文件监听自动热重载

// 本二进制是 GUI 程序：设为 Windows 子系统，避免启动时报一个黑控制台窗口。
#![windows_subsystem = "windows"]

mod autostart;
mod config_ui;
mod icon;
mod server_runtime;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use config_ui::ServerConfigUi;
use rust_frp_util::init_logging;
use serde::Deserialize;
use server_runtime::{ConnState, RuntimeCmd};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::{Builder, Manager, WindowEvent};

/// 共享的最新运行状态（状态线程写、get_status 命令读）
struct LatestStatus {
    state: ConnState,
    clients: Vec<String>,
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
    clients: Vec<String>,
    message: String,
}

/// set_autostart 入参
#[derive(Deserialize)]
struct SetAutostartPayload {
    enable: bool,
}

/// 计算配置文件路径：可执行文件同级目录下的 frps-win.toml
fn config_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("frps-win.toml")
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
fn reload(state: tauri::State<AppState>) {
    let _ = state.cmd_tx.send(RuntimeCmd::Reload);
}

#[tauri::command]
fn get_status(state: tauri::State<AppState>) -> StatusResponse {
    let l = state.latest.lock().unwrap();
    StatusResponse {
        state: format!("{:?}", l.state),
        text: l.state.text(),
        clients: l.clients.clone(),
        message: l.message.clone(),
    }
}

#[tauri::command]
fn load_config(state: tauri::State<AppState>) -> Result<ServerConfigUi, String> {
    Ok(ServerConfigUi::load(&state.config_path))
}

#[tauri::command]
fn save_config(state: tauri::State<AppState>, cfg: ServerConfigUi) -> Result<(), String> {
    cfg.save(&state.config_path)?;
    // 运行中的服务端经文件监听自动热重载；主动补发 reload 双保险
    let _ = state.cmd_tx.send(RuntimeCmd::Reload);
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

/// 单实例保护：用本地固定端口做互斥锁（49172，与客户端 GUI 的 49171 错开），
/// 避免「Run 键自启」+「桌面环境就绪」双拉两个实例抢监听端口。
fn ensure_single_instance() -> Option<std::net::TcpListener> {
    match std::net::TcpListener::bind("127.0.0.1:49172") {
        Ok(l) => Some(l),
        Err(e) => {
            log::info!("检测到已有 rust_frps-gui 实例在运行（49172 被占: {e}），本实例退出");
            None
        }
    }
}

fn main() {
    // 单实例：第二个实例直接退出，避免双实例抢监听端口
    let _instance_lock = match ensure_single_instance() {
        Some(l) => l,
        None => return,
    };

    // 文件日志：写到 exe 同级 frps-gui.log，保留 7 天
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let log_file = exe_dir.join("frps-gui.log");
    if let Err(e) = init_logging(log_file.to_str(), Some("info"), 7) {
        eprintln!("初始化日志失败: {e}");
    }
    // init_logging 装的是 tracing 订阅器，这里把 log 门面桥接到 tracing
    let _ = tracing_log::LogTracer::init();
    log::info!(
        "rust_frps-gui (tauri) 启动，工作目录: {}",
        exe_dir.display()
    );

    let cfg_path = config_path();
    log::info!("配置文件路径: {}", cfg_path.display());

    // 加载配置以取得 Dashboard 端口（状态轮询用）；读不到则默认 7500
    let web_port: u16 = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|d| {
            d.get("web_server")
                .and_then(|w| w.get("port"))
                .and_then(|p| p.as_integer())
                .map(|p| p as u16)
        })
        .unwrap_or(7500);

    let runtime = server_runtime::spawn_runtime(cfg_path.clone(), web_port);
    let cmd_tx = runtime.cmd_tx.clone();
    let status_rx = runtime.status_rx;

    let latest = Arc::new(Mutex::new(LatestStatus {
        state: ConnState::Stopped,
        clients: Vec::new(),
        message: "就绪".to_string(),
    }));

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
            let tray_app = app.handle().clone();

            let tray = TrayIconBuilder::with_id("main")
                .icon(icon::status_image(&ConnState::Stopped))
                .tooltip("rust_frp 服务端")
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
                        let _ = tray_cmd.send(RuntimeCmd::Reload);
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
                            std::thread::sleep(std::time::Duration::from_millis(800));
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

            // 启动即运行（托盘服务语义：打开就监听，无需用户再点启动）。
            // 服务端只绑定本地端口，无需等网络就绪。
            let _ = cmd_tx.send(RuntimeCmd::Start);

            // 状态线程：独占 status_rx，刷新共享状态 + 托盘图标
            let latest_t = latest_for_thread.clone();
            let tray_t = tray.clone();
            std::thread::spawn(move || {
                while let Ok(u) = status_rx.recv() {
                    {
                        let mut l = latest_t.lock().unwrap();
                        l.state = u.state.clone();
                        l.clients = u.clients.clone();
                        l.message = u.message.clone();
                    }
                    let _ = tray_t.set_icon(Some(icon::status_image(&u.state)));
                    let _ = tray_t.set_tooltip(Some(format!("rust_frp 服务端 - {}", u.state.text())));
                }
            });

            Ok(())
        })
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            start,
            stop,
            reload,
            get_status,
            load_config,
            save_config,
            get_autostart,
            set_autostart
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
