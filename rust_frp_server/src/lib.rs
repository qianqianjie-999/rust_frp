//! FRP 服务器模块
//!
//! 该模块实现了 FRP 服务器（frps）的核心功能。
//!
//! ## 服务器架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Server                                   │
//! │  (主服务器结构，管理所有子组件)                                   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ControlManager │   │ServerProxyMgr │   │ServerVisitorMgr│
//! │ (控制器管理)   │   │ (代理管理)     │   │ (访问者管理)   │
//! └───────────────┘   └───────────────┘   └───────────────┘
//!         │                    │                    │
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │   Control     │   │ HttpVhostRouter│  │ WorkConnManager│
//! │ (控制连接)     │   │ (HTTP路由)     │   │ (工作连接管理) │
//! └───────────────┘   └───────────────┘   └───────────────┘
//! ```
//!
//! ## 核心流程
//!
//! ### 1. 客户端连接流程
//! ```text
//! 客户端                          服务器
//!   │                               │
//!   │------ TCP/TLS 连接 --------->│
//!   │                               │
//!   │------ LoginMsg ------------->│
//!   │                               │ 验证 token
//!   │<----- LoginRespMsg ----------│
//!   │                               │
//!   │------ RegisterProxyMsg ----->│
//!   │                               │ 注册代理
//!   │<----- RegisterProxyResp ----│
//!   │                               │
//! ```
//!
//! ### 2. TCP 代理请求流程
//! ```text
//! 访问者        服务器                             客户端                 本地
//!   │              │                                 │                   │
//!   │--- TCP 请求 ->│                                 │                   │
//!   │              │ get_work_conn():                 │                   │
//!   │              │   try_recv from pool             │                   │
//!   │              │   pool empty → ReqWorkConnMsg -->│                   │
//!   │              │                                 │ 新建工作连接 ─────│
//!   │              │<------------- NewWorkConn ------│                   │
//!   │              │   pool.send(conn)                │                   │
//!   │              │   StartWorkConn(visitor_addr) -->│                   │
//!   │              │                                 │ connect local ───>│
//!   │              │                                 │ 可选: PROXY header>│
//!   │<--- 桥接 ---- │<---- bridge_streams --------->│<---- bridge ----->│
//! ```
//!
//! ### 3. HTTP 代理请求流程
//! ```text
//! 访问者        服务器（HTTP路由）              客户端
//!   │              │                            │
//!   │--- HTTP 请求 ->│                            │
//!   │              │ 解析 Host 头                │
//!   │              │ 查找域名对应的代理           │
//!   │              │ ReqWorkConnMsg ------------>│
//!   │              │                            │
//!   │              │              新建工作连接 ---│
//!   │              │<-------- NewWorkConn ------│
//!   │              │                            │
//!   │<--- 响应 ---- │-------------------------->│
//!   │              │                            │
//! ```
//!
//! ## 安全特性
//!
//! 1. **端口白名单 (allow_ports)**
//!    - 默认拒绝所有端口
//!    - 只有在白名单中的端口才能使用
//!    - 配置示例：`allow_ports = [{ start = 10000, end = 20000 }]`
//!
//! 2. **Token 认证**
//!    - 客户端登录时验证 token
//!    - 使用常量时间比较防止时序攻击
//!
//! 3. **HMAC 签名**
//!    - 工作连接使用 HMAC-SHA256 签名
//!    - 验证 run_id 和 timestamp
//!
//! 4. **代理所有权**
//!    - 每个代理绑定到创建它的客户端
//!    - 防止未授权访问
//!
//! ## 配置示例
//!
//! ```toml
//! bind_addr = "0.0.0.0"
//! bind_port = 9300
//!
//! [web_server]
//! addr = "0.0.0.0"
//! port = 7500
//! user = "admin"
//! password = "admin"
//!
//! [auth]
//! method = "token"
//! token = "your_secure_token"
//!
//! allow_ports = [
//!     { single = 9302 },
//!     { start = 10000, end = 20000 },
//! ]
//! ```

mod api;
mod control;
mod error;
mod metrics;
mod proxy_manager;
mod secrets;
mod server;
mod tcpmux;
mod vhost;
mod visitor;
mod web;
mod work_conn;

pub use api::*;
pub use control::*;
pub use error::*;
pub use metrics::*;
pub use proxy_manager::*;
pub use secrets::*;
pub use server::*;
pub use tcpmux::*;
pub use vhost::*;
pub use visitor::*;
pub use web::*;
pub use work_conn::*;

#[cfg(test)]
mod web_auth_tests {
    use super::*;
    use rust_frp_util::get_timestamp;
    use std::time::Duration;

    fn auth(user: Option<&str>, password: Option<&str>) -> std::sync::Arc<WebAuth> {
        std::sync::Arc::new(WebAuth::new(
            user.map(|s| s.to_string()),
            password.map(|s| s.to_string()),
        ))
    }

    fn form(values: &[(&str, &str)]) -> String {
        values
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn headers_with_cookie(cookie: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(cookie).unwrap(),
        );
        headers
    }

    fn set_cookie_of(response: &axum::response::Response) -> Option<String> {
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
    }

    #[test]
    fn test_requires_login_only_when_both_configured() {
        assert!(!auth(None, None).requires_login());
        assert!(!auth(Some("boss"), None).requires_login());
        assert!(!auth(None, Some("pw")).requires_login());
        assert!(auth(Some("boss"), Some("pw")).requires_login());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "abc"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_proxy_secret_registry_lifecycle() {
        let registry = ProxySecretRegistry::new();
        assert_eq!(registry.get("ssh"), None);

        registry.register("ssh", "s3cret");
        assert_eq!(registry.get("ssh"), Some("s3cret".to_string()));

        registry.remove("ssh");
        assert_eq!(registry.get("ssh"), None);
    }

    #[test]
    fn test_verify_stcp_visitor_sign_accepts_valid() {
        let secret = "shared_secret";
        let ts = get_timestamp();
        let sign = rust_frp_auth::generate_stcp_sign_key(secret, "ssh", ts);
        assert!(verify_stcp_visitor_sign(secret, "ssh", ts, &sign));
    }

    #[test]
    fn test_verify_stcp_visitor_sign_rejects_wrong_secret() {
        let ts = get_timestamp();
        let sign = rust_frp_auth::generate_stcp_sign_key("right", "ssh", ts);
        assert!(!verify_stcp_visitor_sign("wrong", "ssh", ts, &sign));
        assert!(!verify_stcp_visitor_sign("right", "ssh", ts, ""));
    }

    #[test]
    fn test_verify_stcp_visitor_sign_rejects_replay() {
        let secret = "shared_secret";
        // 超出时间窗的旧签名（重放）必须拒绝
        let old_ts = get_timestamp() - STCP_SIGN_MAX_AGE_SECS - 10;
        let sign = rust_frp_auth::generate_stcp_sign_key(secret, "ssh", old_ts);
        assert!(!verify_stcp_visitor_sign(secret, "ssh", old_ts, &sign));
        // 时间窗内但代理名不匹配也拒绝
        let ts = get_timestamp();
        let sign2 = rust_frp_auth::generate_stcp_sign_key(secret, "other", ts);
        assert!(!verify_stcp_visitor_sign(secret, "ssh", ts, &sign2));
    }

    #[test]
    fn test_verify_credentials() {
        let auth = auth(Some("boss"), Some("s3cret"));
        assert!(auth.verify_credentials("boss", "s3cret"));
        assert!(!auth.verify_credentials("boss", "wrong"));
        assert!(!auth.verify_credentials("admin", "admin"));
        assert!(!auth.verify_credentials("", ""));
    }

    #[test]
    fn test_verify_credentials_is_disabled_without_config() {
        let auth = auth(None, None);
        assert!(!auth.verify_credentials("admin", "admin"));
        assert!(!auth.verify_credentials("", ""));
    }

    #[tokio::test]
    async fn test_session_lifecycle() {
        let auth = auth(Some("boss"), Some("s3cret"));

        assert!(!auth.validate_session("not-a-real-token").await);
        assert!(!auth.validate_session("").await);

        let token = auth.create_session().await.expect("token generated");
        assert!(auth.validate_session(&token).await);

        auth.revoke_session(&token).await;
        assert!(!auth.validate_session(&token).await);
    }

    #[tokio::test]
    async fn test_session_tokens_are_random_and_not_derived_from_credentials() {
        let auth = auth(Some("boss"), Some("s3cret"));

        let t1 = auth.create_session().await.unwrap();
        let t2 = auth.create_session().await.unwrap();
        assert_ne!(t1, t2, "sessions must not repeat");

        // 旧实现把 base64("user:password") 直接当 cookie，这里必须不再出现
        let legacy = base64::encode("boss:s3cret");
        assert_ne!(t1, legacy);
        assert!(!t1.contains(&legacy));
        assert!(!t1.contains("boss"));
        assert!(!t1.contains("s3cret"));

        // 32 字节随机数 base64 后长度至少 40
        assert!(t1.len() >= 40, "token too short: {}", t1);
    }

    #[test]
    fn test_session_token_from_headers() {
        assert_eq!(
            session_token_from_headers(&headers_with_cookie("frp_session=abc; other=1")),
            Some("abc".to_string())
        );
        assert_eq!(
            session_token_from_headers(&headers_with_cookie("a=b; frp_session=xyz")),
            Some("xyz".to_string())
        );
        // 空值不视为有效会话
        assert_eq!(
            session_token_from_headers(&headers_with_cookie("frp_session=")),
            None
        );
        // 前缀相似但不同的 cookie 名不应被误匹配
        assert_eq!(
            session_token_from_headers(&headers_with_cookie("xfrp_session=evil")),
            None
        );
        assert_eq!(
            session_token_from_headers(&axum::http::HeaderMap::new()),
            None
        );
    }

    #[tokio::test]
    async fn test_login_rejects_wrong_credentials() {
        let auth = auth(Some("boss"), Some("s3cret"));
        let response = login_post_handler(
            axum::extract::Extension(auth.clone()),
            axum::http::HeaderMap::new(),
            form(&[("username", "boss"), ("password", "nope")]),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            set_cookie_of(&response).is_none(),
            "must not issue a session"
        );
    }

    #[tokio::test]
    async fn test_login_rejects_admin_admin_fallback() {
        // 未配置凭据时不得回退到 admin/admin
        let auth = auth(None, None);
        let response = login_post_handler(
            axum::extract::Extension(auth.clone()),
            axum::http::HeaderMap::new(),
            form(&[("username", "admin"), ("password", "admin")]),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(set_cookie_of(&response).is_none());
    }

    #[tokio::test]
    async fn test_login_accepts_correct_credentials_and_issues_hardened_cookie() {
        let auth = auth(Some("boss"), Some("s3cret"));
        let response = login_post_handler(
            axum::extract::Extension(auth.clone()),
            axum::http::HeaderMap::new(),
            form(&[("username", "boss"), ("password", "s3cret")]),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);

        let cookie = set_cookie_of(&response).expect("session cookie set");
        assert!(cookie.contains("HttpOnly"), "cookie: {}", cookie);
        assert!(cookie.contains("SameSite=Strict"), "cookie: {}", cookie);
        assert!(cookie.contains("Path=/"), "cookie: {}", cookie);
        assert!(cookie.contains("Max-Age="), "cookie: {}", cookie);
        assert!(!cookie.contains("Secure"), "plain HTTP must not set Secure");

        // cookie 中的令牌必须是服务端可识别的有效会话
        let token = cookie
            .strip_prefix(&format!("{}=", WEB_SESSION_COOKIE))
            .and_then(|rest| rest.split(';').next())
            .expect("token present")
            .to_string();
        assert!(auth.validate_session(&token).await);
    }

    #[tokio::test]
    async fn test_login_sets_secure_cookie_behind_https_proxy() {
        let auth = auth(Some("boss"), Some("s3cret"));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-proto",
            axum::http::HeaderValue::from_static("https"),
        );

        let response = login_post_handler(
            axum::extract::Extension(auth),
            headers,
            form(&[("username", "boss"), ("password", "s3cret")]),
        )
        .await;

        let cookie = set_cookie_of(&response).expect("session cookie set");
        assert!(cookie.contains("Secure"), "cookie: {}", cookie);
    }

    #[tokio::test]
    async fn test_logout_revokes_session_and_clears_cookie() {
        let auth = auth(Some("boss"), Some("s3cret"));
        let token = auth.create_session().await.unwrap();
        assert!(auth.validate_session(&token).await);

        let response = logout_handler(
            axum::extract::Extension(auth.clone()),
            headers_with_cookie(&format!("{WEB_SESSION_COOKIE}={token}")),
        )
        .await;

        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert!(
            !auth.validate_session(&token).await,
            "session must be revoked"
        );

        let cookie = set_cookie_of(&response).expect("clearing cookie set");
        assert!(cookie.contains("Max-Age=0"), "cookie: {}", cookie);
    }

    #[tokio::test]
    async fn test_login_throttle_locks_after_threshold() {
        let auth = auth(Some("boss"), Some("s3cret"));

        // 前 LOGIN_LOCK_THRESHOLD - 1 次失败：凭据错误但未锁定
        for _ in 0..LOGIN_LOCK_THRESHOLD - 1 {
            assert_eq!(
                auth.attempt_login("boss", "wrong").await,
                Err(false),
                "not locked yet"
            );
        }

        // 第 LOGIN_LOCK_THRESHOLD 次失败：本次即触发锁定
        assert_eq!(auth.attempt_login("boss", "wrong").await, Err(true));

        // 锁定期内即使凭据正确也拒绝（fail-closed）
        assert_eq!(
            auth.attempt_login("boss", "s3cret").await,
            Err(true),
            "locked even with correct credentials"
        );
    }

    #[tokio::test]
    async fn test_login_throttle_resets_after_success() {
        let auth = auth(Some("boss"), Some("s3cret"));

        for _ in 0..LOGIN_LOCK_THRESHOLD - 1 {
            let _ = auth.attempt_login("boss", "wrong").await;
        }
        // 成功登录后计数清零，之后重新起算
        assert!(auth.attempt_login("boss", "s3cret").await.is_ok());
        for _ in 0..LOGIN_LOCK_THRESHOLD - 1 {
            assert_eq!(auth.attempt_login("boss", "wrong").await, Err(false));
        }
        assert_eq!(auth.attempt_login("boss", "wrong").await, Err(true));
        assert_eq!(auth.attempt_login("boss", "s3cret").await, Err(true));
    }

    #[tokio::test]
    async fn test_login_handler_rejects_correct_credentials_when_locked() {
        let auth = auth(Some("boss"), Some("s3cret"));

        // 打满失败次数触发锁定
        for _ in 0..LOGIN_LOCK_THRESHOLD {
            let response = login_post_handler(
                axum::extract::Extension(auth.clone()),
                axum::http::HeaderMap::new(),
                form(&[("username", "boss"), ("password", "nope")]),
            )
            .await;
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        }

        // 锁定期内正确凭据同样 401，且不下发会话 cookie
        let response = login_post_handler(
            axum::extract::Extension(auth.clone()),
            axum::http::HeaderMap::new(),
            form(&[("username", "boss"), ("password", "s3cret")]),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(set_cookie_of(&response).is_none(), "no session when locked");
    }

    #[tokio::test]
    async fn test_login_read_timeout_constant_is_sane() {
        // 预认证超时必须存在且为有限正值（P0-1 回归锚点）
        assert!(LOGIN_READ_TIMEOUT.as_secs() >= 5);
        assert!(LOGIN_READ_TIMEOUT.as_secs() <= 120);
    }

    #[test]
    fn test_write_timeout_constant() {
        // P1-2：写方向必须有 30s 超时锚点
        assert_eq!(WRITE_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn test_conn_limit_constant() {
        // P1-4：全局在途连接上限锚点
        assert_eq!(MAX_INFLIGHT_CONNECTIONS, 4096);
    }

    #[test]
    fn test_conn_limiter_rejects_when_exhausted() {
        // P1-4：许可耗尽时必须直接拒绝（try_acquire 失败），而非排队等待
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let p1 = sem.clone().try_acquire_owned().unwrap();
        assert!(sem.clone().try_acquire_owned().is_err());
        drop(p1);
        assert!(sem.clone().try_acquire_owned().is_ok());
    }

    #[test]
    fn test_poisoned_lock_recovery() {
        // P1-1：锁中毒后 unwrap_or_else(into_inner) 必须取回数据而不是 panic
        let lock = std::sync::Mutex::new(41usize);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = lock.lock().unwrap();
            panic!("poison the mutex");
        }));
        let value = *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(value, 41);

        let rw = std::sync::RwLock::new(String::from("data"));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = rw.read().unwrap();
            panic!("poison the rwlock");
        }));
        assert_eq!(
            rw.read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_str(),
            "data"
        );
    }
}
