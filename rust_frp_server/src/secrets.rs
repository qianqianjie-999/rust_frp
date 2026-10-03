//! STCP/XTCP 共享密钥登记与访问签名校验

use rust_frp_util::get_timestamp;

use crate::*;

/// 仅 stcp/xtcp 类型且配置了 secret_key 的代理会注册；
/// 访问者请求到达时据此校验签名（fail-closed：查不到即拒绝）。
pub struct ProxySecretRegistry {
    keys: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl Default for ProxySecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxySecretRegistry {
    pub fn new() -> Self {
        Self {
            keys: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册代理共享密钥（stcp/xtcp 代理注册成功后调用）
    pub fn register(&self, proxy_name: &str, secret_key: &str) {
        self.keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(proxy_name.to_string(), secret_key.to_string());
    }

    /// 查询代理共享密钥
    pub fn get(&self, proxy_name: &str) -> Option<String> {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(proxy_name)
            .cloned()
    }

    /// 移除代理共享密钥（代理注销/客户端断开时调用）
    pub fn remove(&self, proxy_name: &str) {
        self.keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(proxy_name);
    }
}

/// 进程级共享密钥注册表单例：供 Control::run 等深层调用点零参数获取，
/// 与 global_metrics 同一模式，避免给已超长的构造参数链加参。Server::new 时注册。
static GLOBAL_PROXY_SECRETS: std::sync::OnceLock<std::sync::Arc<ProxySecretRegistry>> =
    std::sync::OnceLock::new();

pub(crate) fn global_proxy_secrets() -> std::sync::Arc<ProxySecretRegistry> {
    GLOBAL_PROXY_SECRETS.get().cloned().unwrap_or_else(|| {
        let r = std::sync::Arc::new(ProxySecretRegistry::new());
        let _ = GLOBAL_PROXY_SECRETS.set(r.clone());
        r
    })
}

/// 校验 STCP/XTCP 访问签名（fail-closed + 常量时间比较 + 防重放时间窗）
///
/// # 校验规则
///
/// 1. 时间戳与服务器当前时间偏差超过 120 秒拒绝（防重放）；
/// 2. 用代理注册的 secret_key 重算签名，常量时间比较（防时序侧信道）。
pub(crate) fn verify_stcp_visitor_sign(
    secret_key: &str,
    proxy_name: &str,
    timestamp: i64,
    provided_sign: &str,
) -> bool {
    let now = get_timestamp();
    if (now - timestamp).abs() > STCP_SIGN_MAX_AGE_SECS {
        log::warn!(
            "STCP/XTCP visitor sign rejected for {}: timestamp drift {}s exceeds {}s",
            proxy_name,
            now - timestamp,
            STCP_SIGN_MAX_AGE_SECS
        );
        return false;
    }
    let expected = rust_frp_auth::generate_stcp_sign_key(secret_key, proxy_name, timestamp);
    constant_time_eq(provided_sign, &expected)
}
