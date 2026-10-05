//! # rust_frp_auth - FRP 认证模块
//!
//! 本模块负责 FRP 协议中的身份认证和授权验证。
//!
//! ## 认证方法
//!
//! ### 1. Token 认证（默认）
//!
//! 基于预共享令牌（PSK）的简单认证方式：
//! - 服务器和客户端配置相同的 token
//! - 登录时验证 token 是否匹配
//!
//! ### 2. OIDC 认证（可选）
//!
//! 基于 OpenID Connect 的企业级认证：
//! - 支持 SSO 单点登录
//! - 支持 OAuth 2.0 第三方认证
//!
//! ## 安全特性
//!
//! - **常量时间比较**：使用 `constant_time_compare` 防止时序攻击
//! - **HMAC-SHA256**：工作连接签名使用 HMAC-SHA256 算法
//! - **SHA256 密钥派生**：从 token 派生出加密密钥
//!
//! ## 签名验证流程
//!
//! ```text
//! Client                          Server
//!   |                               |
//!   |--- LoginMsg (token) --------->|
//!   |                               | [验证 token]
//!   |<-- LoginRespMsg (run_id) -----|
//!   |                               |
//!   |--- NewWorkConnMsg (sign_key)->|
//!   |                               | [使用 run_id + token 验证签名]
//!   |<-- StartWorkConnMsg ----------|
//! ```

use async_trait::async_trait;
use base64::Engine as _;
use ring::digest;
use ring::hmac;
use ring::signature;
use rust_frp_config::{AuthConfig, OidcConfig};

/// 认证模块错误类型
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,

    #[error("token is required for token auth")]
    TokenRequired,

    #[error("unsupported auth method: {0}")]
    UnsupportedMethod(String),

    #[error("OIDC config is required for OIDC auth")]
    OidcConfigRequired,

    #[error("encryption key not set")]
    EncryptionKeyNotSet,

    #[error("HMAC signing failed")]
    HmacSignError,

    #[error("internal error: {0}")]
    Internal(String),
}

/// 安全比较两个字节切片
///
/// # 安全性
///
/// 使用 `ring::constant_time::verify_slices_are_equal` 实现常量时间比较，
/// 防止时序攻击（Timing Attack）。
///
/// # 时序攻击说明
///
/// 普通字符串比较会在第一个不匹配字符处立即返回，
/// 攻击者可以通过测量响应时间推断密码内容。
/// 常量时间比较确保比较时间与输入无关。
///
/// # 参数
///
/// - `a`: 第一个字节切片
/// - `b`: 第二个字节切片
///
/// # 返回值
///
/// - `true`: 两个切片相等
/// - `false`: 长度不同或不相等
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    rust_frp_util::constant_time_eq(a, b)
}

/// 认证验证器 trait - 定义认证接口
///
/// # 实现者
///
/// - `TokenAuthVerifier`: Token 认证实现
/// - `OidcAuthVerifier`: OIDC 认证实现
///
/// # 验证方法
///
/// - `verify_login`: 验证客户端登录
/// - `verify_work_conn`: 验证工作连接
#[async_trait]
pub trait AuthVerifier {
    /// 验证登录请求
    ///
    /// # 参数
    ///
    /// - `user`: 用户名
    /// - `token`: 认证令牌
    async fn verify_login(
        &self,
        user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 验证工作连接
    ///
    /// # 参数
    ///
    /// - `user`: 用户名
    /// - `token`: 认证令牌
    async fn verify_work_conn(
        &self,
        user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Token 认证验证器 - 基于预共享令牌的认证
///
/// # 认证流程
///
/// ```text
/// 1. 客户端配置 token
/// 2. 登录时发送 LoginMsg { token: "xxx" }
/// 3. 服务器使用 constant_time_compare 验证
/// ```
///
/// # 安全性
///
/// - 使用常量时间比较防止时序攻击
/// - Token 直接比较，不经过哈希
pub struct TokenAuthVerifier {
    /// 服务器配置的令牌
    token: String,
}

impl TokenAuthVerifier {
    /// 创建新的 Token 验证器
    ///
    /// # 参数
    ///
    /// - `token`: 服务器配置的令牌
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
        }
    }

    /// 生成 HMAC-SHA256 签名
    ///
    /// # 签名算法
    ///
    /// ```text
    /// sign = HMAC-SHA256(token, token + timestamp)
    /// ```
    ///
    /// # 用途
    ///
    /// 用于工作连接的签名验证
    ///
    /// # 参数
    ///
    /// - `timestamp`: 时间戳（毫秒）
    ///
    /// # 返回值
    ///
    /// Base64 编码的签名字符串
    pub fn generate_sign(&self, timestamp: i64) -> String {
        let msg = format!("{}{}", self.token, timestamp);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.token.as_bytes());
        let tag = hmac::sign(&key, msg.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
    }
}

/// 生成 STCP/XTCP 访问签名密钥（基于代理共享密钥 secret_key）
///
/// # 签名算法
///
/// ```text
/// sign_key = Base64(HMAC-SHA256(secret_key, "stcp:" + proxy_name + ":" + timestamp))
/// ```
///
/// # 用途
///
/// STCP/XTCP 访问者请求建立连接时，用访问者本地配置的 `secret_key`
/// （与服务端代理注册的 `secret_key` 一致）对 `proxy_name + timestamp` 签名，
/// 服务端用代理注册时保存的 secret_key 重新计算并常量时间比较，
/// 证明访问者持有共享密钥且请求非重放。
///
/// # 参数
///
/// - `secret_key`: 共享密钥（访问者配置与服务端代理配置必须一致）
/// - `proxy_name`: 要访问的代理名称
/// - `timestamp`: 请求时间戳（秒）
///
/// # 返回值
///
/// Base64 编码的签名字符串
pub fn generate_stcp_sign_key(secret_key: &str, proxy_name: &str, timestamp: i64) -> String {
    let msg = format!("stcp:{}:{}", proxy_name, timestamp);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, secret_key.as_bytes());
    let tag = hmac::sign(&hmac_key, msg.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

#[async_trait]
impl AuthVerifier for TokenAuthVerifier {
    /// 验证登录令牌
    async fn verify_login(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if constant_time_compare(token.as_bytes(), self.token.as_bytes()) {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid token",
            )))
        }
    }

    /// 验证工作连接令牌
    ///
    /// 工作连接验证使用与登录相同的令牌
    async fn verify_work_conn(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.verify_login(_user, token).await
    }
}

/// OIDC 认证验证器 - 基于 OpenID Connect 的认证（**服务端**）
///
/// # 认证流程
///
/// ```text
/// 1. 客户端从 OIDC Provider 取得 token
/// 2. 登录时发送 LoginMsg { token: "<JWT>" }
/// 3. frps 校验 JWT 签名与声明：
///    a. 拉取 {issuer}/.well-known/openid-configuration（OIDC Discovery）
///    b. 拉取 jwks_uri 指向的 JWKS，按 JWT header 的 kid 选公钥
///    c. 用 ring 验证 RS256 / ES256 签名
///    d. 校验 iss / aud / exp（可按配置跳过）
/// ```
///
/// JWKS 在内存中缓存（TTL 1 小时）；请求携带未知 `kid` 时立即刷新一次，
/// 以支持 IdP 轮转签名密钥。
///
/// # 配置要求
///
/// ```toml
/// [auth]
/// method = "oidc"
///
/// [auth.oidc]
/// issuer = "https://issuer.example.com"
/// audience = "frp-server"
/// ```
///
/// # 安全说明
///
/// - **只接受非对称签名算法（RS256 / ES256）**：显式拒绝 `none` 与 `HS*`，
///   避免「算法混淆」攻击（把 alg 改成 HS256 后，用公开的 RSA 公钥当 HMAC 密钥）。
/// - 签名失败、issuer 不一致、受众不符、token 过期、尚未生效一律拒绝（fail-closed）。
pub struct OidcAuthVerifier {
    /// OIDC 发行者 URL
    issuer: String,
    /// 受众（为空时跳过 `aud` 校验）
    audience: String,
    /// 是否跳过 `exp` 校验
    skip_expiry_check: bool,
    /// 是否跳过 `iss` 校验
    skip_issuer_check: bool,
    /// 出站 HTTP 选项（TLS 校验 / 自定义 CA / 超时）
    http: rust_frp_net::http::HttpOptions,
    /// JWKS 缓存
    cache: tokio::sync::Mutex<Option<JwksCache>>,
    /// 已通过登录校验的 subject 集合（供工作连接复核，与原版语义一致）
    subjects: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// JWKS 中的单个公钥（RSA 取 n/e，EC 取 x/y）
#[derive(Debug, Clone)]
struct Jwk {
    kid: String,
    alg: String,
    kty: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

/// JWKS 缓存条目
struct JwksCache {
    jwks_uri: String,
    keys: Vec<Jwk>,
    fetched_at: std::time::Instant,
}

/// JWKS 缓存有效期
const JWKS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// OIDC 端点请求超时
const OIDC_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl OidcAuthVerifier {
    /// 创建新的 OIDC 验证器
    ///
    /// 不在构造期发起任何网络请求：Discovery 与 JWKS 延迟到首次校验 token 时拉取，
    /// 这样 IdP 短暂不可用不会导致 frps 启动失败（与原版行为一致）。
    ///
    /// # 参数
    ///
    /// - `oidc_config`: OIDC 配置
    pub fn new(oidc_config: &OidcConfig) -> Self {
        Self {
            issuer: oidc_config.issuer.clone(),
            audience: oidc_config.audience.clone(),
            skip_expiry_check: oidc_config.skip_expiry_check,
            skip_issuer_check: oidc_config.skip_issuer_check,
            http: oidc_http_options(oidc_config),
            cache: tokio::sync::Mutex::new(None),
            subjects: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// 拉取 OIDC Discovery 文档，返回 `jwks_uri`
    async fn discover_jwks_uri(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let resp = rust_frp_net::http::get(&url, &self.http)
            .await
            .map_err(deny)?;
        if !resp.is_success() {
            return Err(deny(format!(
                "OIDC discovery at {url} returned HTTP {}",
                resp.status
            )));
        }
        let doc: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| deny(format!("invalid OIDC discovery document: {e}")))?;

        // 发现文档声明的 issuer 必须与配置一致（除非显式跳过 iss 校验）
        if !self.skip_issuer_check {
            if let Some(iss) = doc.get("issuer").and_then(|v| v.as_str()) {
                if normalize_issuer(iss) != normalize_issuer(&self.issuer) {
                    return Err(deny(format!(
                        "OIDC discovery issuer mismatch: expected '{}', got '{}'",
                        self.issuer, iss
                    )));
                }
            }
        }

        doc.get("jwks_uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| deny("OIDC discovery document has no jwks_uri".to_string()))
    }

    /// 拉取并解析 JWKS
    async fn fetch_jwks(
        &self,
        jwks_uri: &str,
    ) -> Result<Vec<Jwk>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = rust_frp_net::http::get(jwks_uri, &self.http)
            .await
            .map_err(deny)?;
        if !resp.is_success() {
            return Err(deny(format!(
                "JWKS at {jwks_uri} returned HTTP {}",
                resp.status
            )));
        }
        let doc: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| deny(format!("invalid JWKS document: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| deny("JWKS document has no keys array".to_string()))?;

        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let get = |name: &str| k.get(name).and_then(|v| v.as_str()).map(|s| s.to_string());
            out.push(Jwk {
                kid: get("kid").unwrap_or_default(),
                alg: get("alg").unwrap_or_default(),
                kty: get("kty").unwrap_or_default(),
                n: get("n"),
                e: get("e"),
                x: get("x"),
                y: get("y"),
            });
        }
        if out.is_empty() {
            return Err(deny("JWKS contains no keys".to_string()));
        }
        Ok(out)
    }

    /// 取当前 JWKS（缓存过期或 `kid` 未命中时刷新）
    async fn keys(
        &self,
        kid: Option<&str>,
    ) -> Result<Vec<Jwk>, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self.cache.lock().await;
        let (stale, cached_uri, unknown_kid) = match guard.as_ref() {
            Some(c) => (
                c.fetched_at.elapsed() > JWKS_TTL,
                c.jwks_uri.clone(),
                kid.is_some_and(|k| !c.keys.iter().any(|key| key.kid == k)),
            ),
            None => (true, String::new(), false),
        };
        if !stale && !unknown_kid {
            return Ok(guard.as_ref().expect("cache present").keys.clone());
        }
        let jwks_uri = if cached_uri.is_empty() {
            self.discover_jwks_uri().await?
        } else {
            cached_uri
        };
        let keys = self.fetch_jwks(&jwks_uri).await?;
        *guard = Some(JwksCache {
            jwks_uri,
            keys: keys.clone(),
            fetched_at: std::time::Instant::now(),
        });
        Ok(keys)
    }

    /// 校验 JWT 并返回其 `sub`（subject）
    ///
    /// 校验步骤：解析 header → 选公钥 → 验签 → 校验 iss / aud / exp / nbf。
    async fn verify_token(
        &self,
        token: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(deny(
                "Invalid JWT: expected 3 parts (header.payload.signature)".to_string(),
            ));
        }
        let (header_b64, payload_b64, signature_b64) = (parts[0], parts[1], parts[2]);

        let header: serde_json::Value = serde_json::from_slice(&b64_decode(header_b64)?)
            .map_err(|e| deny(format!("Invalid JWT header: {e}")))?;
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg != "RS256" && alg != "ES256" {
            return Err(deny(format!(
                "Unsupported JWT alg {alg:?}: only RS256 and ES256 are accepted"
            )));
        }
        let kid = header.get("kid").and_then(|v| v.as_str());

        let keys = self.keys(kid).await?;
        let key = select_key(&keys, kid, alg)?;

        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = b64_decode(signature_b64)?;
        verify_signature(key, alg, signing_input.as_bytes(), &signature)?;

        let claims: serde_json::Value = serde_json::from_slice(&b64_decode(payload_b64)?)
            .map_err(|e| deny(format!("Invalid JWT claims: {e}")))?;

        // iss
        if !self.skip_issuer_check && !self.issuer.is_empty() {
            let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
            if normalize_issuer(iss) != normalize_issuer(&self.issuer) {
                return Err(deny(format!(
                    "JWT issuer mismatch: expected '{}', got '{}'",
                    self.issuer, iss
                )));
            }
        }

        // aud（字符串或数组，任一匹配即可）
        if !self.audience.is_empty() {
            let ok = match claims.get("aud") {
                Some(serde_json::Value::String(s)) => s == &self.audience,
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .any(|v| v.as_str() == Some(self.audience.as_str())),
                _ => false,
            };
            if !ok {
                return Err(deny(format!(
                    "JWT audience mismatch: expected '{}'",
                    self.audience
                )));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if !self.skip_expiry_check {
            if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
                if exp <= now {
                    return Err(deny("JWT token has expired".to_string()));
                }
            }
        }
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > now + 60 {
                return Err(deny("JWT token is not yet valid".to_string()));
            }
        }

        Ok(claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }
}

#[async_trait]
impl AuthVerifier for OidcAuthVerifier {
    /// 登录校验：完整验证 JWT，并记下 subject 供后续工作连接复核
    async fn verify_login(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sub = self.verify_token(token).await?;
        if !sub.is_empty() {
            if let Ok(mut set) = self.subjects.lock() {
                set.insert(sub);
            }
        }
        Ok(())
    }

    /// 工作连接校验：JWT 必须有效，且 subject 必须已完成过登录
    /// （防止「登录用 A 的 token、工作连接换 B 的 token」）
    async fn verify_work_conn(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sub = self.verify_token(token).await?;
        let seen = self.subjects.lock().is_ok_and(|set| set.contains(&sub));
        if !seen {
            return Err(deny(format!(
                "OIDC subject {sub:?} has not completed a login on this server"
            )));
        }
        Ok(())
    }
}

/// OIDC 客户端：以 `client_credentials` 模式向 IdP 换取访问令牌
///
/// 对齐原版 frp 的 `OidcAuthProvider`（go-oauth2 `clientcredentials`）。
/// 每次 [`OidcClientCredentials::fetch_access_token`] 都会发起一次令牌请求，
/// 调用方按 `expires_in` 自行决定缓存与刷新时机。
pub struct OidcClientCredentials {
    client_id: String,
    client_secret: String,
    audience: String,
    scope: String,
    token_endpoint_url: String,
    /// 附加端点参数（排序后持有，保证请求可复现）
    extra_params: Vec<(String, String)>,
    http: rust_frp_net::http::HttpOptions,
}

/// 令牌端点返回的访问令牌
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OidcToken {
    /// 访问令牌
    pub access_token: String,
    /// 有效期（秒）；IdP 未返回时为 0
    #[serde(default)]
    pub expires_in: i64,
}

impl OidcClientCredentials {
    /// 由 OIDC 配置构造
    pub fn new(oidc_config: &OidcConfig) -> Self {
        let mut extra_params: Vec<(String, String)> = oidc_config
            .additional_endpoint_params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        extra_params.sort();
        Self {
            client_id: oidc_config.client_id.clone(),
            client_secret: oidc_config.client_secret.clone(),
            audience: oidc_config.audience.clone(),
            scope: oidc_config.scope.clone(),
            token_endpoint_url: oidc_config.token_endpoint_url.clone(),
            extra_params,
            http: oidc_http_options(oidc_config),
        }
    }

    /// 向令牌端点发起 `client_credentials` 请求，返回访问令牌
    pub async fn fetch_access_token(
        &self,
    ) -> Result<OidcToken, Box<dyn std::error::Error + Send + Sync>> {
        let mut params: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
        ];
        if !self.audience.is_empty() {
            params.push(("audience", self.audience.as_str()));
        }
        if !self.scope.is_empty() {
            params.push(("scope", self.scope.as_str()));
        }
        for (k, v) in &self.extra_params {
            params.push((k.as_str(), v.as_str()));
        }

        let resp = rust_frp_net::http::post_form(&self.token_endpoint_url, &params, &self.http)
            .await
            .map_err(deny)?;
        if !resp.is_success() {
            return Err(deny(format!(
                "OIDC token endpoint returned HTTP {}: {}",
                resp.status,
                resp.body.trim()
            )));
        }
        serde_json::from_str::<OidcToken>(&resp.body)
            .map_err(|e| deny(format!("invalid OIDC token response: {e}")))
    }
}

/// 由 OIDC 配置构造出站 HTTP 选项（TLS 校验 / 自定义 CA / 超时）
fn oidc_http_options(oidc_config: &OidcConfig) -> rust_frp_net::http::HttpOptions {
    let ca_file = oidc_config.trusted_ca_file.trim();
    rust_frp_net::http::HttpOptions {
        tls_verify: !oidc_config.insecure_skip_verify,
        ca_file: (!ca_file.is_empty()).then(|| ca_file.to_string()),
        timeout: OIDC_HTTP_TIMEOUT,
    }
}

/// 构造鉴权失败错误（统一映射为 `PermissionDenied`）
fn deny(msg: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        msg,
    ))
}

/// issuer 比较时忽略结尾斜杠（`https://idp/` 与 `https://idp` 等价）
fn normalize_issuer(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// base64 解码：兼容 JOSE 的 base64url（无填充）与标准 base64
fn b64_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|e| deny(format!("Failed to decode base64: {e}")))
}

/// 按 JWT header 的 `kid` 选取验签公钥
///
/// 未带 `kid` 时仅在「候选唯一」的情况下接受，避免在多密钥场景下 guess。
fn select_key<'a>(
    keys: &'a [Jwk],
    kid: Option<&str>,
    alg: &str,
) -> Result<&'a Jwk, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(kid) = kid {
        return keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| deny(format!("no JWKS key matches kid {kid:?}")));
    }
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| k.alg.is_empty() || k.alg == alg)
        .collect();
    match candidates.as_slice() {
        [only] => Ok(only),
        _ => Err(deny(format!(
            "JWT has no kid and JWKS has {} candidate key(s)",
            candidates.len()
        ))),
    }
}

/// 用 ring 验证 JWT 签名（RS256 / ES256）
///
/// - RS256：由 JWK 的 `n` / `e` 拼出 PKCS#1 DER 公钥，走 RSA PKCS#1 v1.5 + SHA-256
/// - ES256：由 JWK 的 `x` / `y` 拼出未压缩点（`0x04 || X || Y`），
///   走 P-256 + SHA-256 的 **FIXED**（r||s）验签，正是 JOSE 的签名格式
fn verify_signature(
    key: &Jwk,
    alg: &str,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match alg {
        "RS256" => {
            if key.kty != "RSA" {
                return Err(deny(format!(
                    "JWT alg RS256 requires an RSA key, got kty={:?}",
                    key.kty
                )));
            }
            let n = b64_decode(key.n.as_deref().unwrap_or(""))?;
            let e = b64_decode(key.e.as_deref().unwrap_or(""))?;
            if n.is_empty() || e.is_empty() {
                return Err(deny("RSA JWK is missing n or e".to_string()));
            }
            let der = rsa_pkcs1_der(&n, &e);
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der)
                .verify(msg, sig)
                .map_err(|_| deny("JWT RS256 signature verification failed".to_string()))
        }
        "ES256" => {
            if key.kty != "EC" {
                return Err(deny(format!(
                    "JWT alg ES256 requires an EC key, got kty={:?}",
                    key.kty
                )));
            }
            let x = b64_decode(key.x.as_deref().unwrap_or(""))?;
            let y = b64_decode(key.y.as_deref().unwrap_or(""))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(deny(
                    "ES256 JWK x/y must each be 32 bytes (P-256)".to_string(),
                ));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(msg, sig)
                .map_err(|_| deny("JWT ES256 signature verification failed".to_string()))
        }
        other => Err(deny(format!("unsupported JWT alg {other:?}"))),
    }
}

/// DER 长度编码（<128 用短格式，否则长格式）
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut l = len;
    while l > 0 {
        bytes.push((l & 0xff) as u8);
        l >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

/// DER INTEGER 编码（去前导零，最高位为 1 时补 0x00）
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let need_pad = !b.is_empty() && (b[0] & 0x80) != 0;
    let content_len = b.len() + usize::from(need_pad);
    let mut out = vec![0x02];
    out.extend_from_slice(&der_len(content_len));
    if need_pad {
        out.push(0x00);
    }
    out.extend_from_slice(b);
    out
}

/// 由 RSA 模数 / 指数拼出 PKCS#1 `RSAPublicKey` 的 DER 编码
///
/// ring 0.16 的 `UnparsedPublicKey` 对 RSA 算法期望输入即该 DER 结构。
fn rsa_pkcs1_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = der_integer(n);
    body.extend_from_slice(&der_integer(e));
    let mut out = vec![0x30];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(&body);
    out
}

/// 认证管理器 - 统一管理认证和加密
///
/// # 职责
///
/// 1. 管理认证验证器
/// 2. 生成和管理加密密钥
/// 3. 提供数据加密/解密接口
///
/// # 加密密钥派生
///
/// 从认证 token 派生出加密密钥：
/// ```text
/// encryption_key = SHA256(token)
/// ```
pub struct AuthManager {
    /// 认证验证器
    verifier: Box<dyn AuthVerifier + Send + Sync>,

    /// 加密密钥（SHA256(token)）
    encryption_key: Option<Vec<u8>>,

    /// 静态 token（`auth.additionalScopes` 含 heartBeats 时用于心跳签名）
    token: Option<String>,

    /// 额外签名范围（对齐原版 `auth.additionalScopes`）
    additional_scopes: Vec<String>,
}

impl AuthManager {
    /// 创建认证管理器
    ///
    /// # 参数
    ///
    /// - `auth_config`: 认证配置
    ///
    /// # 返回值
    ///
    /// - 成功: `Ok(AuthManager)`
    /// - 失败: 认证方法不支持或配置缺失
    pub fn new(auth_config: &AuthConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // 根据认证方法创建验证器
        let verifier: Box<dyn AuthVerifier + Send + Sync> = match auth_config.method.as_str() {
            "token" => {
                if let Some(token) = &auth_config.token {
                    Box::new(TokenAuthVerifier::new(token))
                } else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "token is required for token auth",
                    )));
                }
            }
            "oidc" => {
                if let Some(oidc_config) = &auth_config.oidc {
                    Box::new(OidcAuthVerifier::new(oidc_config))
                } else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "oidc config is required for oidc auth",
                    )));
                }
            }
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported auth method: {}", auth_config.method),
                )));
            }
        };

        // 从 token 派生加密密钥
        let encryption_key = auth_config
            .token
            .as_ref()
            .map(|token| Self::generate_encryption_key(token));

        Ok(Self {
            verifier,
            encryption_key,
            token: auth_config.token.clone(),
            additional_scopes: auth_config.additional_scopes.clone().unwrap_or_default(),
        })
    }

    /// `additionalScopes` 是否包含 `heartBeats`
    pub fn heartbeats_scope_enabled(&self) -> bool {
        self.additional_scopes.iter().any(|s| s == "heartBeats")
    }

    /// 生成心跳签名（`additionalScopes` 含 `heartBeats` 且配置了静态 token 时）
    ///
    /// # 算法
    ///
    /// ```text
    /// privilege_key = Base64(HMAC-SHA256(token, "ping:" + timestamp))
    /// ```
    ///
    /// 域分隔前缀 `ping:` 与工作连接签名隔离，避免签名跨协议重放。
    pub fn ping_privilege_key(&self, timestamp: i64) -> Option<String> {
        if !self.heartbeats_scope_enabled() {
            return None;
        }
        let token = self.token.as_deref()?;
        let msg = format!("ping:{timestamp}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
        let tag = hmac::sign(&key, msg.as_bytes());
        Some(base64::engine::general_purpose::STANDARD.encode(tag.as_ref()))
    }

    /// 校验心跳签名（常量时间比较；未启用 scope 或无 token 时返回 `Ok`）
    ///
    /// fail-closed：启用 `heartBeats` scope 后，缺少/错误的签名都会被拒绝。
    pub fn verify_ping_privilege_key(
        &self,
        timestamp: i64,
        privilege_key: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.heartbeats_scope_enabled() {
            return Ok(());
        }
        let expected = self.ping_privilege_key(timestamp).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "heartbeats scope enabled but no static token configured",
            )
        })?;
        let ok = rust_frp_util::constant_time_eq(expected.as_bytes(), privilege_key.as_bytes());
        if ok {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "token in heartbeat doesn't match token from configuration",
            )))
        }
    }

    /// 生成加密密钥
    ///
    /// # 算法
    ///
    /// 使用 SHA256 哈希函数对 token 进行哈希：
    /// ```text
    /// key = SHA256(token)
    /// ```
    ///
    /// # 用途
    ///
    /// 用于端到端加密和工作连接签名
    fn generate_encryption_key(token: &str) -> Vec<u8> {
        let mut hasher = digest::Context::new(&digest::SHA256);
        hasher.update(token.as_bytes());
        hasher.finish().as_ref().to_vec()
    }

    /// 获取加密密钥
    ///
    /// # 返回值
    ///
    /// - `Some(&[u8])`: 加密密钥的引用
    /// - `None`: 未设置密钥（未配置 token）
    pub fn encryption_key(&self) -> Option<&[u8]> {
        self.encryption_key.as_deref()
    }

    // 应用层加密（原 encrypt/decrypt 桩）已移除：此前为明文透传的空实现，
    // 会对"配置了密钥 = 已加密"形成假象。本项目仅提供 TLS 传输加密，
    // encryption_key 仅用于工作连接签名（generate_work_conn_sign_key）。

    /// 验证登录请求
    ///
    /// # 参数
    ///
    /// - `user`: 用户名
    /// - `token`: 认证令牌
    pub async fn verify_login(
        &self,
        user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.verifier.verify_login(user, token).await
    }

    /// 验证工作连接
    ///
    /// # 参数
    ///
    /// - `user`: 用户名
    /// - `token`: 认证令牌
    pub async fn verify_work_conn(
        &self,
        user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.verifier.verify_work_conn(user, token).await
    }

    /// 生成工作连接签名密钥
    ///
    /// # 签名算法
    ///
    /// ```text
    /// sign_key = Base64(HMAC-SHA256(encryption_key, "work_conn:" + run_id))
    /// ```
    ///
    /// # 用途
    ///
    /// 工作连接建立时，客户端发送此签名证明身份
    ///
    /// # 验证流程
    ///
    /// ```text
    /// Client                                          Server
    ///   |                                               |
    ///   | generate_sign(run_id) -> sign_key             |
    ///   |                                               |
    ///   |--- NewWorkConnMsg { sign_key: "xxx" } ------->|
    ///   |                                               | [服务器也用相同算法计算签名]
    ///   |                                               | [比较签名是否一致]
    ///   |<-- StartWorkConnMsg --------------------------|
    /// ```
    ///
    /// # 参数
    ///
    /// - `run_id`: 客户端运行 ID
    ///
    /// # 返回值
    ///
    /// - 成功: Base64 编码的签名密钥
    /// - 失败: 加密密钥未设置
    pub async fn generate_work_conn_sign_key(
        &self,
        run_id: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(key) = &self.encryption_key {
            let msg = format!("work_conn:{}", run_id);
            let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
            let tag = hmac::sign(&hmac_key, msg.as_bytes());
            Ok(base64::engine::general_purpose::STANDARD.encode(tag.as_ref()))
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encryption key not set",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_compare_different() {
        assert!(!constant_time_compare(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_compare_different_length() {
        assert!(!constant_time_compare(b"hello", b"hell"));
        assert!(!constant_time_compare(b"hi", b"hello"));
    }

    #[test]
    fn test_constant_time_compare_empty() {
        assert!(constant_time_compare(b"", b""));
    }

    #[test]
    fn test_generate_stcp_sign_key_deterministic() {
        let a = generate_stcp_sign_key("shared_secret", "ssh_proxy", 1000);
        let b = generate_stcp_sign_key("shared_secret", "ssh_proxy", 1000);
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn test_generate_stcp_sign_key_varies() {
        let base = generate_stcp_sign_key("shared_secret", "ssh_proxy", 1000);
        assert_ne!(
            base,
            generate_stcp_sign_key("shared_secret", "ssh_proxy", 1001)
        );
        assert_ne!(base, generate_stcp_sign_key("shared_secret", "other", 1000));
        assert_ne!(
            base,
            generate_stcp_sign_key("wrong_secret", "ssh_proxy", 1000)
        );
        assert_ne!(base, generate_stcp_sign_key("", "ssh_proxy", 1000));
    }

    #[tokio::test]
    async fn test_token_auth_verify_login_success() {
        let verifier = TokenAuthVerifier::new("secret123");
        let result = verifier.verify_login("user", "secret123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_auth_verify_login_wrong_token() {
        let verifier = TokenAuthVerifier::new("secret123");
        let result = verifier.verify_login("user", "wrong_token").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_token_auth_generate_sign() {
        let verifier = TokenAuthVerifier::new("secret123");
        let sign1 = verifier.generate_sign(1234567890);
        let sign2 = verifier.generate_sign(1234567890);
        assert_eq!(sign1, sign2);
    }

    #[test]
    fn test_token_auth_generate_sign_different_timestamp() {
        let verifier = TokenAuthVerifier::new("secret123");
        let sign1 = verifier.generate_sign(111);
        let sign2 = verifier.generate_sign(222);
        assert_ne!(sign1, sign2);
    }

    #[tokio::test]
    async fn test_token_auth_verify_work_conn() {
        let verifier = TokenAuthVerifier::new("secret123");
        let result = verifier.verify_work_conn("user", "secret123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_auth_manager_new_token() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_auth_manager_new_missing_token() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: None,
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config);
        assert!(manager.is_err());
    }

    #[tokio::test]
    async fn test_auth_manager_unsupported_method() {
        let config = AuthConfig {
            method: "unknown".to_string(),
            token: Some("token".to_string()),
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config);
        assert!(manager.is_err());
    }

    #[tokio::test]
    async fn test_auth_manager_encryption_key() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config).unwrap();
        assert!(manager.encryption_key().is_some());
        assert_eq!(manager.encryption_key().unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_auth_manager_verify_login() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config).unwrap();
        assert!(manager.verify_login("user", "my_token").await.is_ok());
        assert!(manager.verify_login("user", "wrong").await.is_err());
    }

    #[tokio::test]
    async fn test_auth_manager_generate_work_conn_sign_key() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        let manager = AuthManager::new(&config).unwrap();
        let key1 = manager
            .generate_work_conn_sign_key("run_001")
            .await
            .unwrap();
        let key2 = manager
            .generate_work_conn_sign_key("run_001")
            .await
            .unwrap();
        assert_eq!(key1, key2);
        let key3 = manager
            .generate_work_conn_sign_key("run_002")
            .await
            .unwrap();
        assert_ne!(key1, key3);
    }
}

// ---------------------------------------------------------------------------
// OIDC 集成测试：起一个 mock IdP（Discovery + JWKS + Token 端点），
// 用真实密码学签名验证「拉取公钥 → 验签 → 校验声明」的完整链路。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod oidc_tests {
    use super::*;
    use ring::signature::KeyPair as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 测试专用 RSA 私钥（PKCS#8 PEM）。**非生产密钥**，仅用于单元测试签名。
    const RSA_TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwb1rgwWlgOPek
P+Szy9fzavMnW7eQi1ty61PEcMJa1jLHc0dlUDe9VxXO7oYxfINows0/KdWhuLSP
fPov3FrqYWNM/rXkles389GvlNXGNpa0pMSA1qOXPg/6LQL3Ccbi7oKmKDeqPJoN
2gjvYlTvnDdKF7+2wp1xqHZ5tv4VqXi4TXMpjtoAxxAyskGlLYdLy1PlcNTtPdvi
3PSA24lmrbYOzHTdkoUlL6gqDG/Czf2QqQF34oa8P0U5XYkwYJC6THogATyg8BnT
5r+PIdoealO3iljzq9cyNJY0QZ4+GYMhG5LsEwIhKT/aOtUGEmufVpY1vojzDVHu
PFowMho9AgMBAAECggEAA+5Ui9m9/iGsIXyLnRaSFv96L8AjN1+7fQnRjHi8rnxu
QN5d0rE2WgwaKsmgCMiO6aMezTpNOF9epSxyKzsmyr5lEX6X++H74yZrX2pFVwy5
T94J7hrveyZWrHVwnE4bSyFoR3PG8GPi73hnpuRoeGGLznqipVucWWoY9ajw6/eY
pFBFoo/dVzlDazlwNZp/TzLnG1BLDuJ45ttiEHXiX+U9+2h0Q/u8YyYC3vv+Cmuq
LRcd6xTKnudDLJRCAEoN5VHIjW6ToTg7/tftqVEvZSO3Nv2M1u65RGXm1SIAEOYU
RgKSL7piPQzfVDlvOlDp7KaPfir1vXnmkno6A8YFOwKBgQDrJfuVoyLBiHAysJdv
bQXCR/TCykiptwfYxjSyOh4DtGX5WoCeFr1VuBYugGpZVNDDwFI5sRTByqQY866A
OTxghK1OxEjGxU7Qyl9wI4XRPW4HrEYyBQXbe9yhHbc4iLX8LhNhju3YqyxfDU/F
rsi9fL0TYgdfbk2ThLphW6EczwKBgQDAFIqA5XJ0FvzmXTl0rXBlx8+77zoad2z0
ajAAYeygEAcudlS4g+ryqwGRzKnEqDB9nnAGemKGM96KpxZYJPp80XsxORnXV/yX
MCvZeRPrBGGZu/HeNKY9jcGMeRJppExxKhxKjs673eBK4f+UvyQ8ZeWa5NFUoT5R
cP6CwCoTMwKBgQC6fb0xx9fgtVyGVxdC/6v5kSfE9Lj8IHTQryFL2FvFhGT7hZNL
za0LNpwg9SdjAakwFm8f4hkcOKI8R8a1Wq9PvOnV9kXhnsoLPPTD8uhGMfn5i99/
/AvRLkKkZPTSmVn7Tm+Ah+KKW/csy1ng5eW+ohcyMCS4wrozrKhEXm9AcQKBgC7q
FXYsFItkPfrqFCl6XzSM3CEz6gYi2zrLYNQHFut1XrurbT/wAIeq2uRIj8KXrdhQ
xV3fsIbEznshGmUHCyNHawZ3wucE943Z1yvz1biWRlxtOkMiquPn5rkvrR6eYYlW
VrijLr1WEP1ZO7qSAQC7hpwRfUtlYrozlgZLdztfAoGAPv7dDy2sI9lUuP2K31q6
laTwOmCqohPYOYqfAualiGGoOONqCKTXrvB/p33tpccmGtKVZhMZrYPUR3HTPoAw
05Zar30XjeH4MPc6S15kxcUreKsOc81dy1RnbUq5eMuTwfN4K9ekmv0M31EsSdo5
ifGHE5azp2Lav/Kni6rRwBQ=
-----END PRIVATE KEY-----"#;
    /// 上述私钥的模数（base64url，无填充）
    const RSA_TEST_N_B64: &str = "sG9a4MFpYDj3pD_ks8vX82rzJ1u3kItbcutTxHDCWtYyx3NHZVA3vVcVzu6GMXyDaMLNPynVobi0j3z6L9xa6mFjTP615JXrN_PRr5TVxjaWtKTEgNajlz4P-i0C9wnG4u6Cpig3qjyaDdoI72JU75w3She_tsKdcah2ebb-Fal4uE1zKY7aAMcQMrJBpS2HS8tT5XDU7T3b4tz0gNuJZq22Dsx03ZKFJS-oKgxvws39kKkBd-KGvD9FOV2JMGCQukx6IAE8oPAZ0-a_jyHaHmpTt4pY86vXMjSWNEGePhmDIRuS7BMCISk_2jrVBhJrn1aWNb6I8w1R7jxaMDIaPQ";
    /// 指数 65537 的 base64url
    const RSA_TEST_E_B64: &str = "AQAB";

    fn b64u(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn b64u_json(v: &serde_json::Value) -> String {
        b64u(serde_json::to_string(v).unwrap().as_bytes())
    }

    fn rsa_key_pair() -> signature::RsaKeyPair {
        let der_b64: String = RSA_TEST_KEY_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(der_b64)
            .unwrap();
        signature::RsaKeyPair::from_pkcs8(&der).unwrap()
    }

    fn rsa_keys_json(kid: &str) -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{RSA_TEST_N_B64}","e":"{RSA_TEST_E_B64}"}}]}}"#
        )
    }

    /// 生成一次性 P-256 密钥；返回 (私钥, JWKS 的 x, JWKS 的 y)
    fn generate_es256() -> (signature::EcdsaKeyPair, String, String) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let point = key.public_key().as_ref();
        assert_eq!(point.len(), 65);
        let (x, y) = (b64u(&point[1..33]), b64u(&point[33..65]));
        (key, x, y)
    }

    /// 用 RS256 签发一个测试 JWT
    fn sign_rs256(key: &signature::RsaKeyPair, kid: &str, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid});
        let signing_input = format!("{}.{}", b64u_json(&header), b64u_json(claims));
        let rng = ring::rand::SystemRandom::new();
        let mut sig = vec![0u8; key.public().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signing_input}.{}", b64u(&sig))
    }

    /// 用 ES256 签发一个测试 JWT
    fn sign_es256(key: &signature::EcdsaKeyPair, kid: &str, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let signing_input = format!("{}.{}", b64u_json(&header), b64u_json(claims));
        let rng = ring::rand::SystemRandom::new();
        let sig = key.sign(&rng, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64u(sig.as_ref()))
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn claims(issuer: &str, audience: &str, exp_offset: i64, sub: &str) -> serde_json::Value {
        let now = now_secs();
        serde_json::json!({
            "iss": issuer,
            "aud": audience,
            "exp": now + exp_offset,
            "iat": now,
            "sub": sub,
        })
    }

    /// 读取一个完整 HTTP 请求（按 Content-Length 判定结束）
    async fn read_request<S: tokio::io::AsyncRead + Unpin>(sock: &mut S) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = sock.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                let cl = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + cl {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// 起一个 mock OIDC issuer（Discovery + JWKS），返回其端口。
    /// `issuer_override` 用于构造「发现文档 issuer 与配置不一致」的场景。
    async fn spawn_issuer(keys_json: String, issuer_override: Option<String>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let keys_json = keys_json.clone();
                let issuer_override = issuer_override.clone();
                let base = format!("http://127.0.0.1:{port}");
                tokio::spawn(async move {
                    let req = read_request(&mut sock).await;
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = if path.starts_with("/.well-known/openid-configuration") {
                        let issuer = issuer_override.unwrap_or(base);
                        format!("{{\"issuer\":\"{issuer}\",\"jwks_uri\":\"http://127.0.0.1:{port}/jwks\"}}")
                    } else if path.starts_with("/jwks") {
                        keys_json
                    } else {
                        "{}".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        port
    }

    fn oidc_cfg(issuer: &str, audience: &str) -> OidcConfig {
        OidcConfig {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_der_encoding_shape() {
        // 最高位为 1 的模数需要补 0x00 前缀
        let n = vec![0x80u8; 4];
        let e = vec![0x01u8, 0x00, 0x01];
        let der = rsa_pkcs1_der(&n, &e);
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..9], &[0x02, 0x05, 0x00, 0x80, 0x80, 0x80, 0x80]);
        assert_eq!(&der[9..], &[0x02, 0x03, 0x01, 0x00, 0x01]);

        // 前导零被去除
        let der = rsa_pkcs1_der(&[0x00, 0x01, 0xff], &[0x01, 0x00, 0x01]);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 0x02);
        assert_eq!(&der[4..6], &[0x01, 0xff]);
    }

    #[tokio::test]
    async fn test_oidc_rs256_discovery_jwks_and_verify() {
        let key = rsa_key_pair();
        let port = spawn_issuer(rsa_keys_json("k1"), None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));
        let token = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", 3600, "alice"));
        assert!(
            verifier.verify_login("alice", &token).await.is_ok(),
            "RS256 token should be accepted"
        );
    }

    #[tokio::test]
    async fn test_oidc_es256_verify() {
        let (key, x, y) = generate_es256();
        let keys = format!(
            r#"{{"keys":[{{"kty":"EC","kid":"e1","alg":"ES256","crv":"P-256","x":"{x}","y":"{y}"}}]}}"#
        );
        let port = spawn_issuer(keys, None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));
        let token = sign_es256(&key, "e1", &claims(&issuer, "frp-server", 3600, "bob"));
        assert!(
            verifier.verify_login("bob", &token).await.is_ok(),
            "ES256 token should be accepted"
        );
    }

    #[tokio::test]
    async fn test_oidc_rejects_tampered_payload() {
        let key = rsa_key_pair();
        let port = spawn_issuer(rsa_keys_json("k1"), None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));
        let token = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", 3600, "alice"));
        // 保留原签名，替换 payload 为「攻击者」→ 验签必须失败
        let parts: Vec<&str> = token.split('.').collect();
        let evil = format!(
            "{}.{}.{}",
            parts[0],
            b64u_json(&claims(&issuer, "frp-server", 3600, "attacker")),
            parts[2]
        );
        assert!(verifier.verify_login("attacker", &evil).await.is_err());
    }

    #[tokio::test]
    async fn test_oidc_rejects_wrong_issuer_audience_and_expiry() {
        let key = rsa_key_pair();
        let port = spawn_issuer(rsa_keys_json("k1"), None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));

        // 错误的 iss
        let t = sign_rs256(
            &key,
            "k1",
            &claims("http://evil.example.com", "frp-server", 3600, "u"),
        );
        assert!(verifier.verify_login("u", &t).await.is_err());

        // 错误的 aud
        let t = sign_rs256(&key, "k1", &claims(&issuer, "other-aud", 3600, "u"));
        assert!(verifier.verify_login("u", &t).await.is_err());

        // 已过期
        let t = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", -60, "u"));
        assert!(verifier.verify_login("u", &t).await.is_err());
    }

    #[tokio::test]
    async fn test_oidc_rejects_alg_none_and_unknown_kid() {
        let key = rsa_key_pair();
        let port = spawn_issuer(rsa_keys_json("k1"), None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));

        // alg=none 必须被拒绝（算法混淆防护）
        let header = serde_json::json!({"alg": "none", "typ": "JWT"});
        let none_token = format!(
            "{}.{}.",
            b64u_json(&header),
            b64u_json(&claims(&issuer, "frp-server", 3600, "u"))
        );
        assert!(verifier.verify_login("u", &none_token).await.is_err());

        // kid 未命中 JWKS → 拒绝
        let t = sign_rs256(
            &key,
            "unknown-kid",
            &claims(&issuer, "frp-server", 3600, "u"),
        );
        assert!(verifier.verify_login("u", &t).await.is_err());

        // 结构非法的 token
        assert!(verifier.verify_login("u", "not-a-jwt").await.is_err());
    }

    #[tokio::test]
    async fn test_oidc_rejects_discovery_issuer_mismatch() {
        let key = rsa_key_pair();
        // 发现文档声明的 issuer 与配置不一致
        let port = spawn_issuer(
            rsa_keys_json("k1"),
            Some("http://some-other-issuer.example.com".to_string()),
        )
        .await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));
        let token = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", 3600, "u"));
        assert!(verifier.verify_login("u", &token).await.is_err());
    }

    #[tokio::test]
    async fn test_oidc_work_conn_requires_prior_login_subject() {
        let key = rsa_key_pair();
        let port = spawn_issuer(rsa_keys_json("k1"), None).await;
        let issuer = format!("http://127.0.0.1:{port}");
        let verifier = OidcAuthVerifier::new(&oidc_cfg(&issuer, "frp-server"));

        let alice = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", 3600, "alice"));
        let bob = sign_rs256(&key, "k1", &claims(&issuer, "frp-server", 3600, "bob"));

        // 未登录过的 subject 不能用于工作连接
        assert!(verifier.verify_work_conn("bob", &bob).await.is_err());

        verifier.verify_login("alice", &alice).await.unwrap();
        assert!(verifier.verify_work_conn("alice", &alice).await.is_ok());
        // 换了 subject 的 token 仍被拒绝
        assert!(verifier.verify_work_conn("bob", &bob).await.is_err());
    }

    #[tokio::test]
    async fn test_oidc_client_credentials_fetch_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            let body = r#"{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        let cfg = OidcConfig {
            client_id: "cid".to_string(),
            client_secret: "sec".to_string(),
            audience: "frp-server".to_string(),
            scope: "openid profile".to_string(),
            token_endpoint_url: format!("http://127.0.0.1:{port}/token"),
            ..Default::default()
        };
        let token = OidcClientCredentials::new(&cfg)
            .fetch_access_token()
            .await
            .unwrap();
        assert_eq!(token.access_token, "tok-123");
        assert_eq!(token.expires_in, 3600);

        let req = handle.await.unwrap();
        assert!(req.starts_with("POST /token HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("Content-Type: application/x-www-form-urlencoded"));
        assert!(req.contains("grant_type=client_credentials"));
        assert!(req.contains("client_id=cid"));
        assert!(req.contains("client_secret=sec"));
        assert!(req.contains("audience=frp-server"));
        assert!(req.contains("scope=openid+profile"));
    }

    #[tokio::test]
    async fn test_oidc_client_credentials_reports_http_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut sock).await;
            let body = r#"{"error":"invalid_client"}"#;
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        let cfg = OidcConfig {
            client_id: "cid".to_string(),
            client_secret: "wrong".to_string(),
            token_endpoint_url: format!("http://127.0.0.1:{port}/token"),
            ..Default::default()
        };
        let err = OidcClientCredentials::new(&cfg)
            .fetch_access_token()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("401"), "{err}");
    }

    #[tokio::test]
    async fn test_auth_manager_new_oidc_variants() {
        let ok = AuthConfig {
            method: "oidc".to_string(),
            token: None,
            oidc: Some(oidc_cfg("https://issuer.example.com", "frp-server")),
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        assert!(AuthManager::new(&ok).is_ok());

        let missing = AuthConfig {
            method: "oidc".to_string(),
            token: None,
            oidc: None,
            token_source: None,
            additional_scopes: None,
            ..Default::default()
        };
        assert!(AuthManager::new(&missing).is_err());
    }
    /// additionalScopes heartBeats：签名与校验闭环、错误签名拒绝、未启用放行
    #[test]
    fn test_ping_privilege_key_scope() {
        let cfg_with_scope = AuthConfig {
            method: "token".to_string(),
            token: Some("secret-token".to_string()),
            additional_scopes: Some(vec!["heartBeats".to_string()]),
            ..Default::default()
        };
        let manager = AuthManager::new(&cfg_with_scope).unwrap();
        assert!(manager.heartbeats_scope_enabled());

        let key = manager
            .ping_privilege_key(1728000000)
            .expect("key generated");
        manager
            .verify_ping_privilege_key(1728000000, &key)
            .expect("valid signature must verify");
        manager
            .verify_ping_privilege_key(1728000000, "bad-signature")
            .expect_err("wrong signature must be rejected");
        manager
            .verify_ping_privilege_key(9999999999, &key)
            .expect_err("timestamp mismatch must be rejected");

        // 未启用 scope：不生成、不校验
        let cfg_plain = AuthConfig {
            method: "token".to_string(),
            token: Some("secret-token".to_string()),
            ..Default::default()
        };
        let manager = AuthManager::new(&cfg_plain).unwrap();
        assert!(!manager.heartbeats_scope_enabled());
        assert!(manager.ping_privilege_key(1).is_none());
        manager
            .verify_ping_privilege_key(1, "anything")
            .expect("scope disabled must not verify");
    }
}
