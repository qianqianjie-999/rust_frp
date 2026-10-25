//! GUI 主界面（eframe::App）
//!
//! 布局：顶栏（标题 + 状态灯 + 启动/停止/保存）、中部表单（连接参数 /
//! 访问者列表 / 高级选项）、底栏（状态消息）。
//!
//! 配置保存采用「TOML 手术」：读入现有文档只改写 GUI 管理的键，
//! **保留 proxies / healthChecks 等手工段**，不做结构体整体序列化
//! （toml crate 无法序列化 None，且会丢未知字段）。
//!
//! 托盘（图标 / 菜单 / 显示窗口 / 退出）由独立线程 [`crate::tray`] 负责，
//! 不受本 eframe 循环冻结影响——本文件只把连接状态转发过去更新图标。

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use eframe::egui;
use rust_frp_config::{ConfigLoader, VisitorConfig};

use crate::autostart;
use crate::client_runtime::{http_post, ConnState, RuntimeCmd, RuntimeHandle};
use crate::tray::GuiToTray;

/// 默认管理端口（仅监听 127.0.0.1，供 GUI 状态轮询）
const DEFAULT_WEB_PORT: u16 = 8610;

/// 单个访问者的表单行
#[derive(Clone)]
pub struct VisitorForm {
    pub name: String,
    pub r#type: String,
    pub server_name: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub bind_port: String,
    pub use_encryption: bool,
    pub use_compression: bool,
}

impl Default for VisitorForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            r#type: "stcp".to_string(),
            server_name: String::new(),
            secret_key: String::new(),
            bind_addr: "127.0.0.1".to_string(),
            bind_port: String::new(),
            use_encryption: false,
            use_compression: false,
        }
    }
}

impl VisitorForm {
    fn from_config(v: &VisitorConfig) -> Self {
        Self {
            name: v.name.clone(),
            r#type: v.r#type.clone(),
            server_name: v.server_name.clone(),
            secret_key: v.secret_key.clone().unwrap_or_default(),
            bind_addr: v.bind_addr.clone(),
            bind_port: v.bind_port.to_string(),
            use_encryption: v.use_encryption,
            use_compression: v.use_compression,
        }
    }
}

/// 表单状态（与 frpc-win.toml 双向映射）
pub struct FormState {
    pub config_path: PathBuf,
    pub client_id: String,
    pub server_addr: String,
    pub server_port: String,
    pub work_conn_port: String,
    pub user: String,
    pub token: String,
    pub tls_enable: bool,
    pub ca_file: String,
    pub cert_file: String,
    pub key_file: String,
    pub log_level: String,
    pub web_port: String,
    pub visitors: Vec<VisitorForm>,
}

impl FormState {
    /// 全新默认表单（配置文件不存在时用）
    fn defaults(config_path: PathBuf) -> Self {
        Self {
            config_path,
            client_id: String::new(),
            server_addr: String::new(),
            server_port: "9300".to_string(),
            work_conn_port: String::new(),
            user: String::new(),
            token: String::new(),
            tls_enable: true,
            ca_file: "ca.crt".to_string(),
            cert_file: "client.crt".to_string(),
            key_file: "client.key".to_string(),
            log_level: "info".to_string(),
            web_port: DEFAULT_WEB_PORT.to_string(),
            visitors: Vec::new(),
        }
    }

    /// 从配置文件加载表单（解析失败时退回默认值，不阻断 GUI 启动）
    pub fn load(config_path: &Path) -> Self {
        let mut form = Self::defaults(config_path.to_path_buf());
        let path_str = config_path.to_string_lossy().to_string();
        // 非 strict：容忍手工配置里的未知字段
        match ConfigLoader::load_client_config_strict(&path_str, false) {
            Ok(cfg) => {
                form.client_id = cfg.client_id.unwrap_or_default();
                form.server_addr = cfg.server_addr;
                form.server_port = cfg.server_port.to_string();
                form.work_conn_port = cfg
                    .work_conn_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.user = cfg.user.unwrap_or_default();
                form.token = cfg.auth.token.unwrap_or_default();
                if let Some(tls) = &cfg.transport.tls {
                    form.tls_enable = tls.enable;
                    form.ca_file = tls.trusted_ca_file.clone().unwrap_or_default();
                    form.cert_file = tls.cert_file.clone().unwrap_or_default();
                    form.key_file = tls.key_file.clone().unwrap_or_default();
                } else {
                    form.tls_enable = false;
                }
                form.log_level = cfg.log.level.unwrap_or_else(|| "info".to_string());
                form.web_port = cfg.web_server.port.to_string();
                form.visitors = cfg.visitors.iter().map(VisitorForm::from_config).collect();
                log::info!(
                    "已加载配置 {}: {} 个访问者",
                    path_str,
                    form.visitors.len()
                );
            }
            Err(e) => {
                log::warn!("加载配置 {} 失败（{}），使用默认表单", path_str, e);
            }
        }
        form
    }

    /// 保存表单到配置文件（TOML 手术：保留 GUI 不管理的段）
    pub fn save(&self) -> Result<(), String> {
        let server_port = parse_port_nonzero(&self.server_port)
            .ok_or_else(|| format!("控制端口无效: {:?}", self.server_port))?;
        if self.server_addr.trim().is_empty() {
            return Err("服务器地址不能为空".to_string());
        }
        let token = self.token.trim();
        if token.is_empty() {
            return Err("Token 不能为空".to_string());
        }

        // 读入现有文档；解析失败（含文件不存在）时从空文档开始
        let mut doc: toml::Table = std::fs::read_to_string(&self.config_path)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .unwrap_or_default();

        doc.insert("server_addr".into(), self.server_addr.trim().into());
        doc.insert("server_port".into(), i64::from(server_port).into());
        set_or_remove(
            &mut doc,
            "work_conn_port",
            parse_port_nonzero(&self.work_conn_port).map(i64::from),
        );
        set_or_remove_str(&mut doc, "client_id", non_empty(&self.client_id));
        set_or_remove_str(&mut doc, "user", non_empty(&self.user));

        let auth = table_mut(&mut doc, "auth");
        auth.insert("method".into(), "token".into());
        set_or_remove_str(auth, "token", non_empty(&self.token));

        let transport = table_mut(&mut doc, "transport");
        transport.insert("protocol".into(), "tcp".into());
        let tls = table_mut(transport, "tls");
        tls.insert("enable".into(), self.tls_enable.into());
        set_or_remove_str(tls, "trusted_ca_file", non_empty(&self.ca_file));
        set_or_remove_str(tls, "cert_file", non_empty(&self.cert_file));
        set_or_remove_str(tls, "key_file", non_empty(&self.key_file));

        // 访问者列表整体重建（表单是唯一事实来源）
        let mut visitors: Vec<toml::Value> = Vec::with_capacity(self.visitors.len());
        for v in &self.visitors {
            let bind_port = parse_port_nonzero(&v.bind_port)
                .ok_or_else(|| format!("访问者 {:?} 的本地端口无效", v.name))?;
            if v.name.trim().is_empty() {
                return Err("存在未填名称的访问者".to_string());
            }
            if v.server_name.trim().is_empty() {
                return Err(format!("访问者 {:?} 未填要访问的代理名", v.name));
            }
            let mut t = toml::Table::new();
            t.insert("name".into(), v.name.trim().into());
            t.insert("type".into(), v.r#type.clone().into());
            t.insert("server_name".into(), v.server_name.trim().into());
            set_or_remove_str(&mut t, "secret_key", non_empty(&v.secret_key));
            t.insert("bind_addr".into(), v.bind_addr.trim().into());
            t.insert("bind_port".into(), i64::from(bind_port).into());
            if v.use_encryption {
                t.insert("use_encryption".into(), true.into());
            }
            if v.use_compression {
                t.insert("use_compression".into(), true.into());
            }
            visitors.push(toml::Value::Table(t));
        }
        doc.insert("visitors".into(), toml::Value::Array(visitors));

        // 管理端口：状态轮询专用，强制只监听回环
        let web_port: u16 = self.web_port.trim().parse().unwrap_or(0);
        let ws = table_mut(&mut doc, "web_server");
        ws.insert("addr".into(), "127.0.0.1".into());
        ws.insert("port".into(), i64::from(web_port).into());

        let log_tbl = table_mut(&mut doc, "log");
        log_tbl.insert("level".into(), self.log_level.clone().into());

        let text =
            toml::to_string_pretty(&doc).map_err(|e| format!("配置序列化失败: {e}"))?;
        std::fs::write(&self.config_path, text).map_err(|e| format!("写配置失败: {e}"))?;
        log::info!("配置已保存: {}", self.config_path.display());
        Ok(())
    }
}

/// GUI 应用状态
pub struct GuiApp {
    form: FormState,
    runtime: RuntimeHandle,
    state: ConnState,
    message: String,
    live_visitors: Vec<String>,
    /// 用户意图（点了启动即为 true，直到停止/退出/出错）
    running: bool,
    /// 向托盘线程转发状态（更新图标）
    tray_tx: Sender<GuiToTray>,
    autostart_on: bool,
    /// 已转发给托盘的上一状态（避免每帧重复发送）
    last_tray_state: Option<ConnState>,
}

impl GuiApp {
    pub fn new(
        form: FormState,
        runtime: RuntimeHandle,
        tray_tx: Sender<GuiToTray>,
        autostart_on: bool,
    ) -> Self {
        Self {
            form,
            runtime,
            state: ConnState::Stopped,
            message: "就绪".to_string(),
            live_visitors: Vec::new(),
            running: false,
            tray_tx,
            autostart_on,
            last_tray_state: None,
        }
    }

    /// GUI 启动即连接（托盘服务语义：打开就连，不需要用户再点启动）
    pub fn auto_start(&mut self) {
        self.running = true;
        let _ = self.runtime.cmd_tx.send(RuntimeCmd::Start);
    }

    fn start(&mut self) {
        if let Err(e) = self.form.save() {
            self.message = format!("保存失败: {e}");
            return;
        }
        self.running = true;
        let _ = self.runtime.cmd_tx.send(RuntimeCmd::Start);
    }

    fn stop(&mut self) {
        self.running = false;
        let _ = self.runtime.cmd_tx.send(RuntimeCmd::Stop);
    }

    fn save(&mut self) {
        match self.form.save() {
            Ok(()) => {
                self.message = "配置已保存".to_string();
                // 运行中的客户端经文件监听自动热重载；主动补发一个 reload 信号双保险
                if self.running {
                    let port: u16 = self.form.web_port.trim().parse().unwrap_or(0);
                    if port > 0 {
                        // 阻塞 HTTP 放独立线程，避免卡住 GUI 线程
                        std::thread::spawn(move || {
                            let _ = http_post(port, "/reload");
                        });
                    }
                }
            }
            Err(e) => self.message = format!("保存失败: {e}"),
        }
    }

    fn toggle_autostart(&mut self, on: bool) {
        match autostart::set_enabled(on) {
            Ok(()) => {
                self.autostart_on = on;
                let _ = self.tray_tx.send(GuiToTray::Autostart(on));
                self.message = if on {
                    "开机自启已开启".to_string()
                } else {
                    "开机自启已关闭".to_string()
                };
            }
            Err(e) => self.message = format!("开机自启设置失败: {e}"),
        }
    }

    fn ui_top(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("rust_frp 客户端");
            ui.colored_label(state_color(&self.state), "●");
            ui.label(self.state.text());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(self.running, egui::Button::new("停止"))
                    .clicked()
                {
                    self.stop();
                }
                if ui
                    .add_enabled(!self.running, egui::Button::new("启动"))
                    .clicked()
                {
                    self.start();
                }
                if ui.button("保存配置").clicked() {
                    self.save();
                }
            });
        });
    }

    fn ui_form(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("连接参数")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("conn_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        labeled_text(ui, "服务器地址", &mut self.form.server_addr, "123.57.86.80", false);
                        labeled_text(ui, "控制端口", &mut self.form.server_port, "9300", false);
                        labeled_text(ui, "工作端口(可空)", &mut self.form.work_conn_port, "留空=自动", false);
                        labeled_text(ui, "客户端 ID(可空)", &mut self.form.client_id, "win-visitor-01", false);
                        labeled_text(ui, "用户名(可空)", &mut self.form.user, "", false);
                        labeled_text(ui, "Token", &mut self.form.token, "", true);
                        ui.label("启用 TLS(mTLS)");
                        ui.checkbox(&mut self.form.tls_enable, "");
                        ui.end_row();
                        labeled_text(ui, "CA 证书", &mut self.form.ca_file, "ca.crt", false);
                        labeled_text(ui, "客户端证书", &mut self.form.cert_file, "client.crt", false);
                        labeled_text(ui, "客户端私钥", &mut self.form.key_file, "client.key", false);
                    });
            });

        egui::CollapsingHeader::new(format!("访问者 ({})", self.form.visitors.len()))
            .default_open(true)
            .show(ui, |ui| {
                self.ui_visitors(ui);
            });

        egui::CollapsingHeader::new("高级选项")
            .default_open(false)
            .show(ui, |ui| {
                egui::Grid::new("adv_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        labeled_text(ui, "管理端口", &mut self.form.web_port, "8610", false);
                        ui.label("日志级别");
                        egui::ComboBox::from_id_salt("log_level_combo")
                            .selected_text(self.form.log_level.clone())
                            .show_ui(ui, |ui| {
                                for lv in ["debug", "info", "warn", "error"] {
                                    ui.selectable_value(
                                        &mut self.form.log_level,
                                        lv.to_string(),
                                        lv,
                                    );
                                }
                            });
                        ui.end_row();
                        ui.label("开机自启");
                        let mut on = self.autostart_on;
                        if ui.checkbox(&mut on, "登录 Windows 后自动运行").changed() {
                            self.toggle_autostart(on);
                        }
                        ui.end_row();
                    });
                ui.label("管理端口仅供本机状态轮询（固定监听 127.0.0.1）。");
                if !self.live_visitors.is_empty() {
                    ui.label(format!("已注册访问者: {}", self.live_visitors.join(", ")));
                }
            });
    }

    fn ui_visitors(&mut self, ui: &mut egui::Ui) {
        let mut remove: Option<usize> = None;
        let count = self.form.visitors.len();
        for idx in 0..count {
            let v = &mut self.form.visitors[idx];
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut v.name)
                        .desired_width(90.0)
                        .hint_text("名称"),
                );
                egui::ComboBox::from_id_salt(format!("vtype_{idx}"))
                    .selected_text(v.r#type.clone())
                    .width(64.0)
                    .show_ui(ui, |ui| {
                        for t in ["stcp", "sudp", "xtcp"] {
                            ui.selectable_value(&mut v.r#type, t.to_string(), t);
                        }
                    });
                ui.add(
                    egui::TextEdit::singleline(&mut v.server_name)
                        .desired_width(110.0)
                        .hint_text("代理名"),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut v.secret_key)
                        .desired_width(100.0)
                        .hint_text("密钥")
                        .password(true),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut v.bind_addr)
                        .desired_width(76.0)
                        .hint_text("127.0.0.1"),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut v.bind_port)
                        .desired_width(52.0)
                        .hint_text("端口"),
                );
                ui.checkbox(&mut v.use_encryption, "加密");
                ui.checkbox(&mut v.use_compression, "压缩");
                if ui.small_button("✕").clicked() {
                    remove = Some(idx);
                }
            });
        }
        if let Some(i) = remove {
            self.form.visitors.remove(i);
        }
        if ui.button("＋ 添加访问者").clicked() {
            self.form.visitors.push(VisitorForm::default());
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. 后台状态推送
        while let Ok(u) = self.runtime.status_rx.try_recv() {
            self.state = u.state.clone();
            self.message = u.message;
            self.live_visitors = u.visitors;
            // 按真实连接状态同步「运行」标志（不论是谁发起的 启动/停止）
            match &self.state {
                ConnState::Stopped | ConnState::Error(_) => self.running = false,
                _ => self.running = true,
            }
            // 仅状态变化时转发给托盘线程更新图标
            if self.last_tray_state.as_ref() != Some(&self.state) {
                self.last_tray_state = Some(self.state.clone());
                let _ = self.tray_tx.send(GuiToTray::Status(self.state.clone()));
            }
        }
        // 2. 关闭窗口 = 收起到托盘（托盘菜单「退出」才真正结束进程）
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        // 3. 三区布局
        egui::TopBottomPanel::top("top").show(ctx, |ui| self.ui_top(ui));
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.message);
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.ui_form(ui));
        });
        // 4. 保活轮询（状态推送的节拍）
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

/// 状态灯颜色
fn state_color(state: &ConnState) -> egui::Color32 {
    match state {
        ConnState::Connected => egui::Color32::from_rgb(34, 197, 94),
        ConnState::Starting | ConnState::Reconnecting => egui::Color32::from_rgb(245, 158, 11),
        ConnState::Stopped => egui::Color32::from_rgb(156, 163, 175),
        ConnState::Error(_) => egui::Color32::from_rgb(239, 68, 68),
    }
}

// ---------- 表单小部件辅助 ----------

fn labeled_text(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    password: bool,
) {
    ui.label(label);
    let mut edit = egui::TextEdit::singleline(value)
        .hint_text(hint)
        .desired_width(220.0);
    if password {
        edit = edit.password(true);
    }
    ui.add(edit);
    ui.end_row();
}

// ---------- TOML 辅助 ----------

/// 取（不存在则建）一个子表
fn table_mut<'a>(doc: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    let entry = doc
        .entry(key)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    entry.as_table_mut().expect("TOML 子表")
}

/// 有值写入、无值删键
fn set_or_remove(table: &mut toml::Table, key: &str, value: Option<i64>) {
    match value {
        Some(v) => {
            table.insert(key.to_string(), toml::Value::from(v));
        }
        None => {
            table.remove(key);
        }
    }
}

fn set_or_remove_str(table: &mut toml::Table, key: &str, value: Option<&str>) {
    match value {
        Some(v) => {
            table.insert(key.to_string(), toml::Value::from(v.to_string()));
        }
        None => {
            table.remove(key);
        }
    }
}

fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// 解析非零端口
fn parse_port_nonzero(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok().filter(|p| *p > 0)
}
