use async_trait::async_trait;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rust_frp_config::{AuthConfig, OidcConfig};
use rust_frp_util::get_timestamp;
use ring::hmac;
use ring::digest;
use base64::encode;

/// 认证验证器 trait
#[async_trait]
pub trait AuthVerifier {
    async fn verify_login(&self, user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn verify_work_conn(&self, user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>>;
}

/// Token 认证验证器
pub struct TokenAuthVerifier {
    token: String,
}

impl TokenAuthVerifier {
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
        }
    }

    /// 生成签名
    pub fn generate_sign(&self, timestamp: i64) -> String {
        let msg = format!("{}{}", self.token, timestamp);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.token.as_bytes());
        let tag = hmac::sign(&key, msg.as_bytes());
        encode(tag.as_ref())
    }
}

#[async_trait]
impl AuthVerifier for TokenAuthVerifier {
    async fn verify_login(&self, _user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        if token == self.token {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid token",
            )))
        }
    }

    async fn verify_work_conn(&self, _user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.verify_login(_user, token).await
    }
}

/// OIDC 认证验证器
pub struct OidcAuthVerifier {
    issuer: String,
    audience: String,
    client_id: String,
    client_secret: String,
    token_endpoint_url: String,
}

impl OidcAuthVerifier {
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
    async fn verify_token(&self, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        // 这里应该实现 OIDC 令牌验证逻辑
        // 暂时简单实现
        Ok(())
    }
}

#[async_trait]
impl AuthVerifier for OidcAuthVerifier {
    async fn verify_login(&self, _user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.verify_token(token).await
    }

    async fn verify_work_conn(&self, _user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.verify_token(token).await
    }
}

/// 认证管理器
pub struct AuthManager {
    verifier: Box<dyn AuthVerifier + Send + Sync>,
    encryption_key: Option<Vec<u8>>,
}

impl AuthManager {
    pub fn new(auth_config: &AuthConfig) -> Result<Self, Box<dyn std::error::Error>> {
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

        // 生成加密密钥
        let encryption_key = if let Some(token) = &auth_config.token {
            Some(Self::generate_encryption_key(token))
        } else {
            None
        };

        Ok(Self {
            verifier,
            encryption_key,
        })
    }

    /// 生成加密密钥
    fn generate_encryption_key(token: &str) -> Vec<u8> {
        let mut hasher = digest::Context::new(&digest::SHA256);
        hasher.update(token.as_bytes());
        hasher.finish().as_ref().to_vec()
    }

    /// 获取加密密钥
    pub fn encryption_key(&self) -> Option<&[u8]> {
        self.encryption_key.as_deref()
    }

    /// 加密数据
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(key) = self.encryption_key.as_ref() {
            // 这里应该实现加密逻辑
            // 暂时简单实现
            Ok(data.to_vec())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encryption key not set",
            )))
        }
    }

    /// 解密数据
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(key) = self.encryption_key.as_ref() {
            // 这里应该实现解密逻辑
            // 暂时简单实现
            Ok(data.to_vec())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "encryption key not set",
            )))
        }
    }

    pub async fn verify_login(&self, user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.verifier.verify_login(user, token).await
    }

    pub async fn verify_work_conn(&self, user: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.verifier.verify_work_conn(user, token).await
    }
}

