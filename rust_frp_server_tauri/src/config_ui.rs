//! 配置 UI 模型：TOML 配置与前端 JSON 之间的双向映射（服务端）
//!
//! 与客户端版同策略：「TOML 手术」只改写 GUI 管理的键，
//! 保留 allow_ports / auth 高级段等手工配置，不做结构体整体序列化。
//!
//! 该模块不依赖任何 GUI 框架，纯数据 + 文件读写，供 Tauri 命令复用。

use rust_frp_config::ConfigLoader;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 整份服务端配置的 UI 模型（与前端 JSON 对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfigUi {
    pub bind_addr: String,
    pub bind_port: String,
    pub token: String,
    pub kcp_bind_port: String,
    pub quic_bind_port: String,
    pub vhost_http_port: String,
    pub vhost_https_port: String,
    pub tcpmux_http_connect_port: String,
    pub work_conn_port: String,
    pub web_addr: String,
    pub web_port: String,
    pub web_user: String,
    pub web_password: String,
    pub log_level: String,
}

impl Default for ServerConfigUi {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            bind_port: "9300".to_string(),
            token: String::new(),
            kcp_bind_port: String::new(),
            quic_bind_port: String::new(),
            vhost_http_port: String::new(),
            vhost_https_port: String::new(),
            tcpmux_http_connect_port: String::new(),
            work_conn_port: String::new(),
            web_addr: "0.0.0.0".to_string(),
            web_port: "7500".to_string(),
            web_user: String::new(),
            web_password: String::new(),
            log_level: "info".to_string(),
        }
    }
}

impl ServerConfigUi {
    /// 从配置文件加载（解析失败时退回默认值，不阻断启动）
    pub fn load(config_path: &Path) -> Self {
        let mut form = Self::default();
        let path_str = config_path.to_string_lossy().to_string();
        match ConfigLoader::load_server_config_strict(&path_str, false) {
            Ok(cfg) => {
                form.bind_addr = cfg.bind_addr;
                form.bind_port = cfg.bind_port.to_string();
                form.token = cfg.auth.token.unwrap_or_default();
                form.kcp_bind_port = cfg.kcp_bind_port.map(|p| p.to_string()).unwrap_or_default();
                form.quic_bind_port = cfg.quic_bind_port.map(|p| p.to_string()).unwrap_or_default();
                form.vhost_http_port = cfg
                    .vhost_http_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.vhost_https_port = cfg
                    .vhost_https_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.tcpmux_http_connect_port = cfg
                    .tcpmux_http_connect_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.work_conn_port = cfg
                    .work_conn_port
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                form.web_addr = if cfg.web_server.addr.is_empty() {
                    "0.0.0.0".to_string()
                } else {
                    cfg.web_server.addr
                };
                form.web_port = cfg.web_server.port.to_string();
                form.web_user = cfg.web_server.user.unwrap_or_default();
                form.web_password = cfg.web_server.password.unwrap_or_default();
                form.log_level = cfg.log.level.unwrap_or_else(|| "info".to_string());
                log::info!(
                    "已加载配置 {}: bind_port={}, dashboard={}",
                    path_str,
                    form.bind_port,
                    form.web_port
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
        let bind_port = parse_port_nonzero(&self.bind_port)
            .ok_or_else(|| format!("控制端口无效: {:?}", self.bind_port))?;
        if self.bind_addr.trim().is_empty() {
            return Err("绑定地址不能为空".to_string());
        }

        // 读入现有文档；解析失败（含文件不存在）时从空文档开始
        let mut doc: toml::Table = std::fs::read_to_string(config_path)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .unwrap_or_default();

        doc.insert("bind_addr".into(), self.bind_addr.trim().into());
        doc.insert("bind_port".into(), i64::from(bind_port).into());

        set_or_remove(
            &mut doc,
            "kcp_bind_port",
            parse_port_nonzero(&self.kcp_bind_port).map(i64::from),
        );
        set_or_remove(
            &mut doc,
            "quic_bind_port",
            parse_port_nonzero(&self.quic_bind_port).map(i64::from),
        );
        set_or_remove(
            &mut doc,
            "vhost_http_port",
            parse_port_nonzero(&self.vhost_http_port).map(i64::from),
        );
        set_or_remove(
            &mut doc,
            "vhost_https_port",
            parse_port_nonzero(&self.vhost_https_port).map(i64::from),
        );
        set_or_remove(
            &mut doc,
            "tcpmux_http_connect_port",
            parse_port_nonzero(&self.tcpmux_http_connect_port).map(i64::from),
        );
        set_or_remove(
            &mut doc,
            "work_conn_port",
            parse_port_nonzero(&self.work_conn_port).map(i64::from),
        );

        // 认证：有 token 才写 method=token；清空即移除
        let auth = table_mut(&mut doc, "auth");
        let token = non_empty(&self.token);
        set_or_remove_str(auth, "token", token);
        match token {
            Some(_) => {
                auth.insert("method".into(), "token".into());
            }
            None => {
                auth.remove("method");
            }
        }

        // Dashboard：port 0 = 禁用；账密可选
        let web = table_mut(&mut doc, "web_server");
        web.insert(
            "addr".into(),
            if self.web_addr.trim().is_empty() {
                "0.0.0.0".into()
            } else {
                self.web_addr.trim().into()
            },
        );
        let web_port: u16 = self.web_port.trim().parse().unwrap_or(0);
        web.insert("port".into(), i64::from(web_port).into());
        set_or_remove_str(web, "user", non_empty(&self.web_user));
        set_or_remove_str(web, "password", non_empty(&self.web_password));

        let log_tbl = table_mut(&mut doc, "log");
        log_tbl.insert("level".into(), self.log_level.clone().into());

        let text = toml::to_string_pretty(&doc).map_err(|e| format!("配置序列化失败: {e}"))?;
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
