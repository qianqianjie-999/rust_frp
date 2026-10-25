//! 系统托盘：独立 OS 线程持有图标与菜单，脱离 eframe 事件循环
//!
//! 为什么要独立线程：窗口隐藏/最小化后 eframe 的 `update()` 循环会停止处理事件，
//! 托盘菜单（显示窗口 / 退出）就再也收不到。把托盘事件放到独立线程、用原生
//! Win32 `ShowWindow(SW_RESTORE)` / `std::process::exit` 响应，窗口处于任何状态
//! （隐藏或最小化）都能可靠动作。

use std::sync::mpsc;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconEvent};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextW, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

use crate::autostart;
use crate::client_runtime::{http_post, ConnState, RuntimeCmd};
use crate::icon;

/// 主窗口标题（与 `eframe::run_native` 传入的一致），用于按标题定位 HWND
const MAIN_TITLE: &str = "rust_frp 客户端";

/// GUI → 托盘线程（图标状态 / 开机自启文本同步）
pub enum GuiToTray {
    Status(ConnState),
    Autostart(bool),
}

/// 托盘线程句柄（GUI 持有发送端）
pub struct TrayHandle {
    pub tx: mpsc::Sender<GuiToTray>,
}

/// 启动托盘线程。
///
/// - `cmd_tx`：转发 启动/停止/退出 到客户端运行时（克隆自 GUI 持有的发送端）
/// - `web_port`：重载配置所用的管理端口（0 表示未配置）
/// - `autostart_on`：初始开机自启状态（决定菜单项勾选文本）
pub fn spawn_tray(
    cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>,
    web_port: u16,
    autostart_on: bool,
) -> TrayHandle {
    let (tx, rx) = mpsc::channel::<GuiToTray>();
    std::thread::Builder::new()
        .name("frpc-gui-tray".into())
        .spawn(move || tray_main(cmd_tx, web_port, autostart_on, rx))
        .expect("托盘线程创建失败");
    TrayHandle { tx }
}

fn tray_main(
    cmd_tx: tokio::sync::mpsc::UnboundedSender<RuntimeCmd>,
    web_port: u16,
    mut autostart_on: bool,
    rx: mpsc::Receiver<GuiToTray>,
) {
    // ---- 菜单（含 id，便于事件分发）----
    let show_item = MenuItem::with_id("show", "显示主窗口", true, None);
    let start_item = MenuItem::with_id("start", "启动", true, None);
    let stop_item = MenuItem::with_id("stop", "停止", true, None);
    let reload_item = MenuItem::with_id("reload", "重载配置", true, None);
    let autostart_item = MenuItem::with_id(
        "autostart",
        if autostart_on { "✓ 开机自启" } else { "开机自启" },
        true,
        None,
    );
    let quit_item = MenuItem::with_id("quit", "退出", true, None);

    let menu = Menu::new();
    let _ = menu.append(&show_item);
    let _ = menu.append(&start_item);
    let _ = menu.append(&stop_item);
    let _ = menu.append(&reload_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&autostart_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    let attrs = tray_icon::TrayIconAttributes {
        tooltip: Some("rust_frp 客户端".to_string()),
        icon: Some(icon::status_icon(&ConnState::Starting)),
        menu: Some(Box::new(menu)),
        ..Default::default()
    };
    let tray = match TrayIcon::new(attrs) {
        Ok(t) => Some(t),
        Err(e) => {
            // 托盘失败不阻断主窗口（个别环境/远程桌面可能创建失败）
            log::error!("托盘图标创建失败: {e}");
            None
        }
    };

    let mut last_state: Option<ConnState> = Some(ConnState::Starting);

    loop {
        // 图标鼠标事件：左键单击/双击 → 显示窗口
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            match event {
                TrayIconEvent::Click { button, .. }
                | TrayIconEvent::DoubleClick { button, .. } => {
                    if matches!(button, tray_icon::MouseButton::Left) {
                        raw_show();
                    }
                }
                _ => {}
            }
        }

        // 菜单事件
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            match event.id.as_ref() {
                "show" => raw_show(),
                "start" => {
                    let _ = cmd_tx.send(RuntimeCmd::Start);
                }
                "stop" => {
                    let _ = cmd_tx.send(RuntimeCmd::Stop);
                }
                "reload" => {
                    if web_port > 0 {
                        let port = web_port;
                        std::thread::spawn(move || {
                            let _ = http_post(port, "/reload");
                        });
                    }
                }
                "autostart" => {
                    autostart_on = !autostart_on;
                    match autostart::set_enabled(autostart_on) {
                        Ok(()) => {
                            let _ = autostart_item.set_text(if autostart_on {
                                "✓ 开机自启"
                            } else {
                                "开机自启"
                            });
                        }
                        Err(e) => {
                            log::error!("开机自启设置失败: {e}");
                            autostart_on = !autostart_on; // 回滚
                        }
                    }
                }
                "quit" => {
                    // 直接通知运行时收摊并退出进程：不依赖 eframe 循环，
                    // 即使主窗口处于隐藏/最小化也能可靠退出
                    let _ = cmd_tx.send(RuntimeCmd::Shutdown);
                    std::thread::sleep(Duration::from_millis(700));
                    std::process::exit(0);
                }
                _ => {}
            }
        }

        // GUI → 托盘 同步（图标状态 / 开机自启文本）
        while let Ok(msg) = rx.try_recv() {
            match msg {
                GuiToTray::Status(state) => {
                    if last_state.as_ref() != Some(&state) {
                        last_state = Some(state.clone());
                        if let Some(tray) = tray.as_ref() {
                            let _ = tray.set_icon(Some(icon::status_icon(&state)));
                            let _ = tray.set_tooltip(Some(format!("rust_frp - {}", state.text())));
                        }
                    }
                }
                GuiToTray::Autostart(on) => {
                    autostart_on = on;
                    let _ = autostart_item.set_text(if on { "✓ 开机自启" } else { "开机自启" });
                }
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 用原生 Win32 API 恢复并前台化主窗口。
///
/// 覆盖「隐藏（Visible=false）」与「最小化（iconic）」两种状态：eframe 的
/// `ViewportCommand::Visible/Minimized` 在窗口隐藏后不可靠（循环可能已停），
/// 而 `ShowWindow(SW_RESTORE)` 是确定性的。按标题定位 HWND，无需持有 eframe
/// 内部句柄。
fn raw_show() {
    let hwnd = find_main_window();
    if hwnd == 0 {
        return;
    }
    unsafe {
        let h: HWND = hwnd as isize;
        ShowWindow(h, SW_RESTORE);
        SetForegroundWindow(h);
    }
}

/// 枚举顶层窗口，返回标题等于 [MAIN_TITLE] 的 HWND（0 表示未找到）
fn find_main_window() -> usize {
    struct FindState {
        found: usize,
    }

    unsafe extern "system" fn cb(hwnd: HWND, lparam: LPARAM) -> i32 {
        let state = &mut *(lparam as *mut FindState);
        let mut buf = [0u16; 256];
        let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
        if len > 0 {
            let text = String::from_utf16_lossy(&buf[..len as usize]);
            if text == MAIN_TITLE {
                state.found = hwnd as usize;
                return 0; // 找到即停止枚举
            }
        }
        1 // 继续枚举
    }

    let mut state = FindState { found: 0 };
    unsafe {
        EnumWindows(Some(cb), &mut state as *mut FindState as LPARAM);
    }
    state.found
}
