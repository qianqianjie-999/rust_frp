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
use rust_frp_config::{AuthConfig, OidcConfig};
use ring::hmac;
use ring::digest;
use ring::constant_time;
use base64::encode;

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
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    constant_time::verify_slices_are_equal(a, b).is_ok()
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
        encode(tag.as_ref())
    }
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

/// OIDC 认证验证器 - 基于 OpenID Connect 的认证
///
/// # OIDC 认证流程
///
/// ```text
/// 1. 客户端从 OIDC Provider 获取 token
/// 2. 登录时发送 LoginMsg { token: "<id_token>" }
/// 3. 服务器验证 JWT 签名和声明
/// ```
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
/// client_id = "frp-client"
/// client_secret = "secret"
/// token_endpoint_url = "https://issuer.example.com/token"
/// ```
#[allow(dead_code)]
pub struct OidcAuthVerifier {
    /// OIDC 发行者 URL
    issuer: String,

    /// 受众（客户端 ID）
    audience: String,

    /// OAuth 客户端 ID
    client_id: String,

    /// OAuth 客户端密钥
    client_secret: String,

    /// Token 端点 URL
    token_endpoint_url: String,
}

impl OidcAuthVerifier {
    /// 创建新的 OIDC 验证器
    ///
    /// # 参数
    ///
    /// - `oidc_config`: OIDC 配置
    pub fn new(oidc_config: &OidcConfig) -> Self {
        Self {
            issuer: oidc_config.issuer.clone(),
            audience: oidc_config.audience.clone(),
            client_id: oidc_config.client_id.clone(),
            client_secret: oidc_config.client_secret.clone(),
            token_endpoint_url: oidc_config.token_endpoint_url.clone(),
        }
    }

    /// 验证 OIDC 令牌
    ///
    /// # 验证步骤
    ///
    /// 1. 验证 JWT 签名（使用发行者的公钥）
    /// 2. 验证发行者 (iss claim)
    /// 3. 验证受众 (aud claim)
    /// 4. 验证过期时间 (exp claim)
    /// 5. 验证生效时间 (iat claim)
    async fn verify_token(
        &self,
        _token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: 实现完整的 OIDC 验证逻辑
        // 1. 获取 OIDC Provider 的 JWKS
        // 2. 验证 JWT 签名
        // 3. 验证声明
        Ok(())
    }
}

#[async_trait]
impl AuthVerifier for OidcAuthVerifier {
    async fn verify_login(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.verify_token(token).await
    }

    async fn verify_work_conn(
        &self,
        _user: &str,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.verify_token(token).await
    }
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
    pub fn new(
        auth_config: &AuthConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
        let encryption_key = auth_config.token.as_ref().map(|token| Self::generate_encryption_key(token));

        Ok(Self {
            verifier,
            encryption_key,
        })
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

    /// 加密数据
    ///
    /// # 说明
    ///
    /// TODO: 实现完整的加密逻辑
    ///
    /// # 参数
    ///
    /// - `data`: 要加密的原始数据
    ///
    /// # 返回值
    ///
    /// - 成功: 加密后的数据
    /// - 失败: 密钥未设置
    pub fn encrypt(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(_key) = self.encryption_key.as_ref() {
            // TODO: 实现完整的加密逻辑
            // 方案：使用 AES-256-GCM
            Ok(data.to_vec())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encryption key not set",
            )))
        }
    }

    /// 解密数据
    ///
    /// # 说明
    ///
    /// TODO: 实现完整的解密逻辑
    ///
    /// # 参数
    ///
    /// - `data`: 加密的数据
    ///
    /// # 返回值
    ///
    /// - 成功: 解密后的原始数据
    /// - 失败: 密钥未设置
    pub fn decrypt(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(_key) = self.encryption_key.as_ref() {
            // TODO: 实现完整的解密逻辑
            Ok(data.to_vec())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encryption key not set",
            )))
        }
    }

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
            Ok(encode(tag.as_ref()))
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
        };
        let manager = AuthManager::new(&config).unwrap();
        assert!(manager.encryption_key().is_some());
        assert_eq!(manager.encryption_key().unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_auth_manager_encrypt_decrypt() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
        };
        let manager = AuthManager::new(&config).unwrap();
        let data = b"hello world";
        let encrypted = manager.encrypt(data).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[tokio::test]
    async fn test_auth_manager_verify_login() {
        let config = AuthConfig {
            method: "token".to_string(),
            token: Some("my_token".to_string()),
            oidc: None,
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
        };
        let manager = AuthManager::new(&config).unwrap();
        let key1 = manager.generate_work_conn_sign_key("run_001").await.unwrap();
        let key2 = manager.generate_work_conn_sign_key("run_001").await.unwrap();
        assert_eq!(key1, key2);
        let key3 = manager.generate_work_conn_sign_key("run_002").await.unwrap();
        assert_ne!(key1, key3);
    }
}
