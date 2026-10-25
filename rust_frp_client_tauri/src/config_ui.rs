//! 配置 UI 模型：TOML 配置与前端 JSON 之间的双向映射
//!
//! 配置保存采用「TOML 手术」：读入现有文档只改写 GUI 管理的键，
//! **保留 proxies / healthChecks 等手工段**，不做结构体整体序列化
//! （toml crate 无法序列化 None，且会丢未知字段）。
//!
//! 该模块不依赖任何 GUI 框架，纯数据 + 文件读写，供 Tauri 命令复用。

use rust_frp_config::{ConfigLoader, VisitorConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 单个访问者的 UI 模型（与前端 JSON 对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorUi {
    pub name: String,
    pub r#type: String,
    pub server_name: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub bind_port: String,
    pub use_encryption: bool,
    pub use_compression: bool,
}

impl VisitorUi {
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

/// 整份客户端配置的 UI 模型（与前端 JSON 对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigUi {
    pub server_addr: String,
    pub server_port: String,
    pub work_conn_port: String,
    pub client_id: String,
    pub user: String,
    pub token: String,
    pub tls_enable: bool,
    pub ca_file: String,
    pub cert_file: String,
    pub key_file: String,
    pub log_level: String,
    pub web_port: String,
    pub visitors: Vec<VisitorUi>,
}

impl Default for ClientConfigUi {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            server_port: "9300".to_string(),
            work_conn_port: String::new(),
            client_id: String::new(),
            user: String::new(),
            token: String::new(),
            tls_enable: true,
            ca_file: "ca.crt".to_string(),
            cert_file: "client.crt".to_string(),
            key_file: "client.key".to_string(),
            log_level: "info".to_string(),
            web_port: "9310".to_string(),
            visitors: Vec::new(),
        }
    }
}

impl ClientConfigUi {
    /// 从配置文件加载（解析失败时退回默认值，不阻断启动）
    pub fn load(config_path: &Path) -> Self {
        let mut form = Self::default();
        let path_str = config_path.to_string_lossy().to_string();
        match ConfigLoader::load_client_config_strict(&path_str, false) {
            Ok(cfg) => {
                form.server_addr = cfg.server_addr;
                form.server_port = cfg.server_port.to_string();
                form.work_conn_port = cfg
                    .work_conn_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.client_id = cfg.client_id.unwrap_or_default();
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
                form.visitors = cfg.visitors.iter().map(VisitorUi::from_config).collect();
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

    /// 保存配置到文件（TOML 手术：保留 GUI 不管理的段）
    pub fn save(&self, config_path: &Path) -> Result<(), String> {
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
        let mut doc: toml::Table = std::fs::read_to_string(config_path)
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
        std::fs::write(config_path, text).map_err(|e| format!("写配置失败: {e}"))?;
        log::info!("配置已保存: {}", config_path.display());
        Ok(())
    }
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
