//! rust_frp Windows GUI 客户端（rust_frpc-gui）
//!
//! 替代命令行 `rust_frpc -c frpc-win.toml` 的常驻方式：
//!
//! - **系统托盘**：图标颜色反映连接状态（绿=已连接 / 琥珀=连接中 / 灰=已停止），
//!   左键单击显示主窗口，右键菜单（显示窗口 / 重载配置 / 开机自启 / 退出）
//! - **主窗口**：连接参数与访问者列表全部表单化，保存即写 frpc-win.toml
//!   （运行中客户端经文件监听自动热重载）
//! - **进程内运行**：后台 tokio 线程直接跑 `rust_frp_client::Client`，
//!   不再依赖命令行进程；管理端口 `GET /status` 提供连接状态
//! - **开机自启**：HKCU\...\Run 注册表项（无需管理员权限）
//!
//! 关闭窗口只是藏到托盘，从托盘菜单选「退出」才真正结束。

#![windows_subsystem = "windows"]

mod app;
mod autostart;
mod client_runtime;
mod font;
mod icon;
mod tray;

use std::path::PathBuf;
use std::time::Duration;

use eframe::egui;

use crate::app::{FormState, GuiApp};
use crate::client_runtime::RuntimeCmd;
use crate::tray::spawn_tray;

fn main() -> eframe::Result<()> {
    // 维护用 CLI 开关（部署脚本/排障用，正常双击启动不带参数）：
    //   --enable-autostart / --disable-autostart  开关机自启注册表项
    //   --autostart-status                         查询当前自启状态
    // 结果写日志（GUI 子系统无控制台），以退出码 0/1 表示成功/失败。
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .iter()
        .any(|a| a == "--enable-autostart" || a == "--disable-autostart")
    {
        let enable = args.iter().any(|a| a == "--enable-autostart");
        // 日志初始化（写 exe 同目录），保证操作结果可追溯
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let _ = std::env::set_current_dir(dir);
                let log_file = dir.join("frpc-gui.log");
                let _ = rust_frp_util::init_logging(log_file.to_str(), Some("info"), 7);
            }
        }
        return match autostart::set_enabled(enable) {
            Ok(()) => Ok(()),
            Err(e) => {
                log::error!("开机自启设置失败: {e}");
                std::process::exit(1);
            }
        };
    }
    if args.iter().any(|a| a == "--autostart-status") {
        let enabled = autostart::is_enabled();
        log::info!("开机自启状态: {}", if enabled { "已启用" } else { "未启用" });
        if !enabled {
            std::process::exit(1);
        }
        return Ok(());
    }

    // 工作目录切到 exe 所在目录：配置里的证书相对路径以此为基准
    // （注册表开机自启启动时 cwd 不确定，必须显式设置）
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::env::set_current_dir(&exe_dir);

    // 日志写文件：GUI 子系统无控制台，stderr 不可见
    let log_file = exe_dir.join("frpc-gui.log");
    if let Err(e) = rust_frp_util::init_logging(log_file.to_str(), Some("info"), 7) {
        eprintln!("rust_frpc-gui: 日志初始化失败: {e}");
    }
    log::info!("rust_frpc-gui 启动，工作目录: {}", exe_dir.display());

    let config_path = exe_dir.join("frpc-win.toml");
    let config_exists = config_path.exists();
    let form = FormState::load(&config_path);
    let web_port: u16 = form.web_port.trim().parse().unwrap_or(0);

    let runtime = client_runtime::spawn_runtime(config_path.clone(), web_port);
    // 留一份发送端：run_native 返回（窗口关闭）后通知 runtime 收摊
    let shutdown_tx = runtime.cmd_tx.clone();

    // ---- 托盘（独立 OS 线程，见 tray.rs）----
    let autostart_on = autostart::is_enabled();
    log::info!(
        "开机自启状态: {}",
        if autostart_on { "已启用" } else { "未启用" }
    );
    let tray = spawn_tray(runtime.cmd_tx.clone(), web_port, autostart_on);

    // ---- 主窗口 ----
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([660.0, 740.0])
            .with_min_inner_size([560.0, 620.0])
            .with_icon(icon::window_icon()),
        ..Default::default()
    };

    let mut gui_app = GuiApp::new(form, runtime, tray.tx, autostart_on);
    // 已有配置则 GUI 启动即连接（托盘服务语义）；无配置时等用户填完手动启动
    if config_exists {
        gui_app.auto_start();
    }

    let result = eframe::run_native(
        "rust_frp 客户端",
        options,
        Box::new(move |cc| {
            // 安装中文字体（egui 默认字体无 CJK 字形）
            if let Some(bytes) = font::load_cjk_font_bytes() {
                install_cjk_font(&cc.egui_ctx, bytes);
            }
            Ok(Box::new(gui_app))
        }),
    );

    // 窗口已关：通知后台 runtime 优雅停止客户端后退出
    let _ = shutdown_tx.send(RuntimeCmd::Shutdown);
    // 留时间给 POST /stop 的优雅退出流程（向服务端发 Disconnect + 排空连接）
    std::thread::sleep(Duration::from_millis(800));
    result.map(|_| ())
}

/// 把中文字体装进 egui 字体栈（proportional / monospace 都置首，其余字形回落默认字体）
fn install_cjk_font(ctx: &egui::Context, bytes: Vec<u8>) {
    use egui::{FontData, FontDefinitions, FontFamily};
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "cjk".to_owned(),
        std::sync::Arc::new(FontData::from_owned(bytes)),
    );
    if let Some(list) = fonts.families.get_mut(&FontFamily::Proportional) {
        list.insert(0, "cjk".to_owned());
    }
    if let Some(list) = fonts.families.get_mut(&FontFamily::Monospace) {
        list.insert(0, "cjk".to_owned());
    }
    ctx.set_fonts(fonts);
}
