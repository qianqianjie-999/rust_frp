//! client 模块测试（原 lib.rs 末尾的 `#[cfg(test)] mod`）。

#[cfg(test)]
mod tls_config_tests {
    use crate::*;
    use rust_frp_config::{ClientConfig, TlsConfig};

    fn config_with_tls(tls: TlsConfig) -> ClientConfig {
        let mut c = ClientConfig::default();
        c.transport.tls = Some(tls);
        c
    }

    /// TLS 关闭 → 不建 TLS 配置
    #[test]
    fn test_tls_disabled_returns_none() {
        let cfg = config_with_tls(TlsConfig {
            enable: false,
            ..TlsConfig::default()
        });
        assert!(build_client_tls_config(&cfg).unwrap().is_none());
    }

    /// 配置了 trusted_ca_file → CA 验证模式
    #[test]
    fn test_tls_with_ca_file() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            trusted_ca_file: Some("/nonexistent/ca.crt".to_string()),
            ..TlsConfig::default()
        });
        // CA 文件不存在时返回 Err（读文件失败），但绝不能静默退化为 insecure
        let r = build_client_tls_config(&cfg);
        assert!(r.is_err(), "missing CA file must not fall back to insecure");
    }

    /// skip_verify = true → 显式跳过（insecure）
    #[test]
    fn test_tls_skip_verify_explicit() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            skip_verify: true,
            ..TlsConfig::default()
        });
        assert!(build_client_tls_config(&cfg).unwrap().is_some());
    }

    /// 默认（无 CA、skip_verify = false）→ fail-closed 拒绝启动
    #[test]
    fn test_tls_default_fail_closed() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            ..TlsConfig::default()
        });
        let err = match build_client_tls_config(&cfg) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("default TLS config must be rejected (fail-closed)"),
        };
        assert!(
            err.contains("fail-closed") || err.contains("skip_verify"),
            "{}",
            err
        );
    }
}

#[cfg(test)]
mod client_manager_tests {
    use crate::*;
    use rust_frp_config::{ClientConfig, ProxyConfig, VisitorConfig};

    fn proxy(name: &str, r#type: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.to_string(),
            r#type: r#type.to_string(),
            ..ProxyConfig::default()
        }
    }

    fn visitor(name: &str) -> VisitorConfig {
        VisitorConfig {
            name: name.to_string(),
            r#type: "stcp".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            ..VisitorConfig::default()
        }
    }

    /// visitor 任务 drop 标记：任务被 abort（future 被 drop）时置位，
    /// 用于从外部断言"任务真的停了"
    struct TaskDropped(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for TaskDropped {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 起一个永不自行结束的 visitor 任务（模拟 accept 循环），
    /// 返回句柄与 drop 标记
    fn spawn_never_ending_visitor_task() -> (
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = flag.clone();
        let handle = tokio::spawn(async move {
            let _guard = TaskDropped(f);
            let (_tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            let _ = rx.recv().await; // 永不完成，只能被 abort
        });
        (handle, flag)
    }

    // 注册为不支持的代理类型：只写入注册表、不启动本地监听，避免端口占用
    #[tokio::test]
    async fn test_proxy_manager_add_status_remove_clear() {
        use rust_frp_core::ProxyManager;
        let mgr = ClientProxyManager::new();

        mgr.add_proxy(proxy("web", "unsupported-for-test"))
            .await
            .unwrap();
        assert_eq!(
            mgr.get_proxy_status("web").await.unwrap(),
            Some("running".to_string())
        );
        assert_eq!(mgr.get_proxy_status("missing").await.unwrap(), None);

        mgr.remove_proxy("web").await.unwrap();
        assert_eq!(mgr.get_proxy_status("web").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_proxy_manager_clear() {
        use rust_frp_core::ProxyManager;
        let mgr = ClientProxyManager::new();
        mgr.add_proxy(proxy("a", "unsupported-for-test"))
            .await
            .unwrap();
        mgr.add_proxy(proxy("b", "unsupported-for-test"))
            .await
            .unwrap();
        mgr.clear().await;
        assert_eq!(mgr.get_proxy_status("a").await.unwrap(), None);
        assert_eq!(mgr.get_proxy_status("b").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_visitor_manager_add_remove_clear() {
        use rust_frp_core::VisitorManager;
        let mgr = ClientVisitorManager::new();

        mgr.add_visitor(visitor("v1")).await.unwrap();
        mgr.add_visitor(visitor("v2")).await.unwrap();
        assert_eq!(mgr.visitors.read().await.len(), 2);

        mgr.remove_visitor("v1").await.unwrap();
        assert_eq!(mgr.visitors.read().await.len(), 1);
        assert!(mgr.visitors.read().await.contains_key("v2"));

        mgr.clear().await;
        assert!(mgr.visitors.read().await.is_empty());
    }

    /// 回归（2026-10-24 生产故障）：重连 clear() 必须 abort 已注册的
    /// visitor 任务。只清配置表不 abort → 旧 listener 占着本地端口，
    /// 新任务 bind 报 AddrInUse 直接退出；且旧 stcp_tx 随旧控制连接关闭，
    /// 旧任务之后 accept 到的连接全部 "channel closed"，隧道静默死亡。
    #[tokio::test]
    async fn test_visitor_manager_clear_aborts_running_tasks() {
        let mgr = ClientVisitorManager::new();
        let (h1, flag1) = spawn_never_ending_visitor_task();
        let (h2, flag2) = spawn_never_ending_visitor_task();
        mgr.register_visitor_task("v1".to_string(), h1).await;
        mgr.register_visitor_task("v2".to_string(), h2).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !flag1.load(std::sync::atomic::Ordering::SeqCst)
                && !flag2.load(std::sync::atomic::Ordering::SeqCst),
            "任务应在运行中"
        );

        mgr.clear().await;
        assert!(
            flag1.load(std::sync::atomic::Ordering::SeqCst),
            "clear() 必须 abort v1 任务"
        );
        assert!(
            flag2.load(std::sync::atomic::Ordering::SeqCst),
            "clear() 必须 abort v2 任务"
        );
        assert!(mgr.visitor_tasks.read().await.is_empty(), "句柄表应清空");

        // clear 之后管理器仍可复用（重连路径会再次注册新任务）
        let (h3, flag3) = spawn_never_ending_visitor_task();
        mgr.register_visitor_task("v3".to_string(), h3).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!flag3.load(std::sync::atomic::Ordering::SeqCst));
        mgr.abort_visitor_task("v3").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(flag3.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// 同名重复注册（热重载/异常重入）必须 abort 旧任务，
    /// 否则两个 accept 循环抢同一个本地端口
    #[tokio::test]
    async fn test_visitor_manager_register_replaces_old_task() {
        let mgr = ClientVisitorManager::new();
        let (old, old_flag) = spawn_never_ending_visitor_task();
        mgr.register_visitor_task("v1".to_string(), old).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!old_flag.load(std::sync::atomic::Ordering::SeqCst));

        let (new, new_flag) = spawn_never_ending_visitor_task();
        mgr.register_visitor_task("v1".to_string(), new).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            old_flag.load(std::sync::atomic::Ordering::SeqCst),
            "同名重新注册应 abort 旧任务"
        );
        assert!(
            !new_flag.load(std::sync::atomic::Ordering::SeqCst),
            "新任务应继续运行"
        );
    }

    /// bind 重试回归：端口被占用时不得放弃（一次失败就 return 会让
    /// visitor 隧道静默消失，只能手动重启 frpc）；端口释放后必须绑定成功
    #[tokio::test]
    async fn test_bind_visitor_listener_retries_until_port_free() {
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = blocker.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);

        let fut = bind_visitor_listener(&addr);
        tokio::pin!(fut);
        // 端口被占：首次尝试立即失败，随后进入 1s 重试等待
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut fut)
                .await
                .is_err(),
            "端口占用期间 bind 不应成功"
        );

        drop(blocker);
        let listener = tokio::time::timeout(std::time::Duration::from_secs(5), fut)
            .await
            .expect("端口释放后应在重试周期内绑定成功");
        assert_eq!(listener.local_addr().unwrap().port(), port);
    }

    /// 空闲端口应立即绑定（重试路径不引入人为延迟）
    #[tokio::test]
    async fn test_bind_visitor_listener_free_port() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listener = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bind_visitor_listener(&format!("127.0.0.1:{}", port)),
        )
        .await
        .expect("空闲端口应立即绑定");
        assert_eq!(listener.local_addr().unwrap().port(), port);
    }

    #[test]
    fn test_work_conn_port_of_default_and_override() {
        let mut cfg = ClientConfig {
            server_port: 7100,
            work_conn_port: None,
            ..ClientConfig::default()
        };
        assert_eq!(work_conn_port_of(&cfg), 8100);

        cfg.work_conn_port = Some(7400);
        assert_eq!(work_conn_port_of(&cfg), 7400);
    }

    /// 工作端口解析优先级：服务器下发 > 客户端配置 > server_port+1000
    #[test]
    fn test_resolve_work_conn_port_precedence() {
        let mut cfg = ClientConfig {
            server_port: 9300,
            work_conn_port: None,
            ..ClientConfig::default()
        };
        // 旧版服务端未下发（0）→ 客户端无配置 → server_port+1000
        assert_eq!(resolve_work_conn_port(&cfg, 0), 10300);
        // 旧版服务端未下发 → 客户端显式配置生效
        cfg.work_conn_port = Some(9500);
        assert_eq!(resolve_work_conn_port(&cfg, 0), 9500);
        // 新版服务端下发真实端口 → 最高优先级（覆盖客户端的错配）
        assert_eq!(resolve_work_conn_port(&cfg, 10300), 10300);
        // visitor 场景：服务端下发自定义端口（如 12000）且客户端无配置 →
        // 必须拨下发值，不能回落 server_port+1000。
        // STCP/XTCP/SUDP visitor 与普通代理共用本解析（见 handle_stcp_visitor_conn）。
        cfg.work_conn_port = None;
        assert_eq!(resolve_work_conn_port(&cfg, 12000), 12000);
        // 旧版服务端（0）+ 客户端无配置 → 仍按 server_port+1000 推算
        assert_eq!(resolve_work_conn_port(&cfg, 0), 10300);
    }

    /// auto 模式降级缓存：直拨失败后 60s 内不再尝试，超时后恢复尝试
    #[test]
    fn test_work_port_degraded_cache() {
        // 确保从"无失败记录"状态开始（清掉其他测试可能留下的标记）
        mark_work_port_ok();
        assert!(work_port_currently_preferred());

        // 标记失败 → 立即不再优先直拨
        mark_work_port_failed();
        assert!(!work_port_currently_preferred());

        // 恢复成功标记 → 重新优先直拨
        mark_work_port_ok();
        assert!(work_port_currently_preferred());
    }

    #[tokio::test]
    async fn test_health_checker_without_config_exits_immediately() {
        // 未配置 health_check 时检查任务应立即返回而不是空转
        let checker = HealthChecker::new(proxy("no-hc", "tcp"));
        let handle = checker.start();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("health checker should exit immediately without health_check config")
            .unwrap();
    }

    #[tokio::test]
    async fn test_arc_config_sharing_is_cheap_and_consistent() {
        // 热路径共享 Arc<ClientConfig>：克隆是 O(1) 指针拷贝，指向同一份配置
        let cfg = ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            ..ClientConfig::default()
        };
        let cfg = Arc::new(cfg);

        let shared = Arc::clone(&cfg);
        assert_eq!(shared.server_addr, cfg.server_addr);
        assert_eq!(shared.server_port, cfg.server_port);
        assert_eq!(Arc::strong_count(&cfg), 2);
    }
}

#[cfg(test)]
mod web_admin_tests {
    use crate::*;
    use axum::body::Body;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_state() -> Arc<WebServerState> {
        Arc::new(WebServerState {
            proxy_manager: Arc::new(ClientProxyManager::new()),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            config_path: None,
            auth_enabled: false,
        })
    }

    fn temp_config_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        dir.join(format!(
            "frpc_admin_test_{tag}_{}",
            rust_frp_util::rand_id(8)
        ))
    }

    fn app_with_auth(auth: Option<(String, String)>) -> Router {
        let state = test_state();
        Router::new()
            .route("/status", get(status_handler))
            .route("/stop", post(stop_handler))
            .route("/reload", post(reload_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                let auth = auth.clone();
                basic_auth_middleware(req, next, auth)
            }))
    }

    fn auth_header(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    }

    #[tokio::test]
    async fn test_admin_api_open_when_no_auth_configured() {
        let app = app_with_auth(None);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_stop_endpoint_notifies_and_returns_ok() {
        let state = test_state();
        let app = Router::new()
            .route("/stop", post(stop_handler))
            .with_state(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/stop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        // 许可位语义：端点在 await 前已 notify，notified() 应立刻返回
        tokio::time::timeout(Duration::from_millis(200), state.stop_notify.notified())
            .await
            .expect("stop signal should be delivered");
    }

    #[tokio::test]
    async fn test_admin_api_rejects_missing_or_wrong_credentials() {
        let app = app_with_auth(Some(("admin".into(), "secret".into())));

        // 无凭据 → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // 密码错误 → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("admin", "wrong"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // 用户名错误 → 401
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("nope", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_admin_api_accepts_correct_credentials() {
        let app = app_with_auth(Some(("admin".into(), "secret".into())));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_reload_handler_signals_waiter() {
        let state = test_state();
        let notify = state.reload_notify.clone();
        let app = Router::new()
            .route("/reload", post(reload_handler))
            .with_state(state);

        let waiter = tokio::spawn(async move { notify.notified().await });
        tokio::task::yield_now().await;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("reload notify should reach the waiter")
            .unwrap();
    }

    #[tokio::test]
    async fn test_status_handler_lists_proxies_and_visitors() {
        let mut mgr = ClientProxyManager::new();
        mgr.set_work_conn_manager(Arc::new(WorkConnManager::new()));
        let state = Arc::new(WebServerState {
            proxy_manager: Arc::new(mgr),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            config_path: None,
            auth_enabled: false,
        });
        state
            .proxy_manager
            .add_proxy(rust_frp_config::ProxyConfig {
                name: "ssh".to_string(),
                r#type: "tcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 0,
                remote_port: Some(6000),
                ..Default::default()
            })
            .await
            .unwrap();
        // 记录一次流量，验证 /status 暴露的累计字节数
        state.proxy_manager.record_traffic("ssh", 123, 456).await;

        let app = Router::new()
            .route("/status", get(status_handler))
            .with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["proxies"][0]["name"], "ssh");
        assert_eq!(json["proxies"][0]["status"], "running");
        assert_eq!(json["proxies"][0]["remote_port"], 6000);
        assert_eq!(json["proxies"][0]["traffic_down"], 123);
        assert_eq!(json["proxies"][0]["traffic_up"], 456);
        assert_eq!(json["visitors"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_parse_basic_credentials() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(
            parse_basic_credentials(&format!("Basic {encoded}")),
            Some(("user".to_string(), "pass".to_string()))
        );
        assert_eq!(parse_basic_credentials("Bearer xyz"), None);
        assert_eq!(parse_basic_credentials("Basic !!!not-base64"), None);
        // 无冒号分隔的解码结果
        assert_eq!(
            parse_basic_credentials(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("nocolon")
            )),
            None
        );
    }
    fn config_app(state: Arc<WebServerState>, auth: Option<(String, String)>) -> Router {
        Router::new()
            .route("/config", get(get_config_handler).put(put_config_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                let auth = auth.clone();
                basic_auth_middleware(req, next, auth)
            }))
    }

    const VALID_CONFIG: &str = "server_addr = \"127.0.0.1\"\nserver_port = 9300\n\n[auth]\nmethod = \"token\"\ntoken = \"abc\"\n";

    #[tokio::test]
    async fn test_config_endpoints_forbidden_without_auth() {
        // 未配置 webServer user/password：GET/PUT /config 一律 403（fail-closed）
        let state = test_state();
        let app = config_app(state, None);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .body(Body::from("server_addr = \"x\""))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    fn state_with_config(
        path: &std::path::Path,
        notify: Arc<tokio::sync::Notify>,
    ) -> Arc<WebServerState> {
        Arc::new(WebServerState {
            proxy_manager: Arc::new(ClientProxyManager::new()),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: notify,
            stop_notify: Arc::new(tokio::sync::Notify::new()),
            config_path: Some(path.to_string_lossy().into_owned()),
            auth_enabled: true,
        })
    }

    #[tokio::test]
    async fn test_get_config_returns_file_content() {
        let path = temp_config_path("get");
        std::fs::write(&path, VALID_CONFIG).unwrap();

        let state = state_with_config(&path, Arc::new(tokio::sync::Notify::new()));
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(body, VALID_CONFIG);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_put_config_valid_writes_and_notifies() {
        let path = temp_config_path("put");
        std::fs::write(
            &path,
            "server_addr = \"old\"\nserver_port = 1\n[auth]\nmethod = \"token\"\ntoken = \"t\"\n",
        )
        .unwrap();

        let notify = Arc::new(tokio::sync::Notify::new());
        let state = state_with_config(&path, notify.clone());
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        let waiter = tokio::spawn(async move { notify.notified().await });
        tokio::task::yield_now().await;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::from(VALID_CONFIG))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // 文件已被原子覆写为新内容，且 reload 通知已发出
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, VALID_CONFIG);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("PUT /config should trigger reload notify")
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_put_config_invalid_rejected_without_touching_file() {
        let path = temp_config_path("put_invalid");
        std::fs::write(&path, VALID_CONFIG).unwrap();

        let state = state_with_config(&path, Arc::new(tokio::sync::Notify::new()));
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        // 缺 auth 段的非法配置 -> 400 且原文件不动
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::from(
                        "server_addr = \"127.0.0.1\"\nserver_port = 99999\n",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), VALID_CONFIG);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod sudp_tests {
    use crate::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// 测试用 FrpConn 适配器（内存双工流缺少 remote_addr，需包一层）
    struct TestConn(tokio::io::DuplexStream);

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl rust_frp_net::FrpConn for TestConn {
        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    /// 本地 UDP 回声服务：回包带 `echo:` 前缀，便于区分会话
    async fn spawn_udp_echo() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        addr
    }

    /// 读取一条 UdpPacket 回包（心跳等控制消息跳过）
    async fn read_udp_reply(peer: &mut tokio::io::DuplexStream) -> rust_frp_core::UdpPacketMsg {
        loop {
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                rust_frp_core::read_message(peer),
            )
            .await
            .expect("reply timeout")
            .expect("reply read");
            match received {
                Message::UdpPacket(packet) => return packet,
                _ => continue,
            }
        }
    }

    /// 代理侧：隧道 UDP 包帧 → 本地 UDP 服务 → 回包按 client_addr 送回
    #[tokio::test]
    async fn test_sudp_proxy_forwards_and_isolates_sessions() {
        let local = spawn_udp_echo().await;
        let (tunnel, mut peer) = tokio::io::duplex(64 * 1024);

        tokio::spawn(serve_sudp_proxy(
            Box::new(TestConn(tunnel)),
            "sudp-test",
            local.to_string(),
        ));

        // 两个不同访问者源地址：回包必须回到各自的 client_addr
        for (client_addr, payload) in [("127.0.0.1:40001", "alpha"), ("127.0.0.1:40002", "beta")] {
            let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                proxy_name: "sudp-test".to_string(),
                data: payload.as_bytes().to_vec(),
                client_addr: Some(client_addr.to_string()),
            });
            rust_frp_core::write_message(&mut peer, &msg).await.unwrap();

            let reply = read_udp_reply(&mut peer).await;
            assert_eq!(
                reply.client_addr.as_deref(),
                Some(client_addr),
                "回包应回到发起会话的访问者地址"
            );
            assert_eq!(
                String::from_utf8_lossy(&reply.data),
                format!("echo:{}", payload)
            );
        }
    }

    /// 隧道写任务按消息帧写入（读侧能还原同一条消息）
    #[tokio::test]
    async fn test_tunnel_writer_frames_messages() {
        let (tunnel, mut peer) = tokio::io::duplex(8 * 1024);
        let out_tx = spawn_tunnel_writer(TestConn(tunnel));

        let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
            proxy_name: "p".to_string(),
            data: vec![1, 2, 3],
            client_addr: Some("127.0.0.1:1".to_string()),
        });
        out_tx.send(msg).await.unwrap();

        match rust_frp_core::read_message(&mut peer).await.unwrap() {
            Message::UdpPacket(packet) => assert_eq!(packet.data, vec![1, 2, 3]),
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

#[cfg(test)]
mod client_traffic_tests {
    use crate::*;

    #[tokio::test]
    async fn test_manager_records_and_snapshots_traffic() {
        let mgr = ClientProxyManager::new();
        assert_eq!(mgr.traffic_snapshot("ssh").await, None);

        mgr.record_traffic("ssh", 100, 200).await;
        assert_eq!(mgr.traffic_snapshot("ssh").await, Some((100, 200)));

        // 累加语义，且不同代理互不影响
        mgr.record_traffic("ssh", 5, 6).await;
        mgr.record_traffic("web", 1, 2).await;
        assert_eq!(mgr.traffic_snapshot("ssh").await, Some((105, 206)));
        assert_eq!(mgr.traffic_snapshot("web").await, Some((1, 2)));
    }
}

#[cfg(test)]
mod token_source_tests {
    use crate::*;
    use rust_frp_config::{ClientConfig, TokenSource};
    use std::io::Write;

    fn base_config() -> ClientConfig {
        ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            ..Default::default()
        }
    }

    /// type = "file"：读取文件内容（去除首尾空白）并写入内存 token
    #[test]
    fn applies_token_from_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("frp_tok_{}.txt", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "  file-token-123  ").unwrap();
        drop(f);

        let mut cfg = base_config();
        cfg.auth.token_source = Some(TokenSource {
            r#type: "file".to_string(),
            file_path: Some(path.to_string_lossy().into_owned()),
            exec: None,
        });
        apply_token_source(&mut cfg).unwrap();
        assert_eq!(cfg.auth.token.as_deref(), Some("file-token-123"));
        let _ = std::fs::remove_file(&path);
    }

    /// type = "file"：文件缺失 → 报错而非静默空 token
    #[test]
    fn missing_file_is_error() {
        let mut cfg = base_config();
        cfg.auth.token_source = Some(TokenSource {
            r#type: "file".to_string(),
            file_path: Some("/nonexistent/frp/token".to_string()),
            exec: None,
        });
        assert!(apply_token_source(&mut cfg).is_err());
        assert!(cfg.auth.token.is_none());
    }

    /// type = "exec"：取 stdout（去除尾部换行）作为 token
    #[test]
    fn applies_token_from_exec() {
        let mut cfg = base_config();
        // 平台自适应：/bin/echo 仅 POSIX 存在，Windows 用 cmd echo
        #[cfg(windows)]
        let exec = Some(vec![
            "cmd".to_string(),
            "/C".to_string(),
            "echo".to_string(),
            "exec-token-9".to_string(),
        ]);
        #[cfg(not(windows))]
        let exec = Some(vec!["/bin/echo".to_string(), "exec-token-9".to_string()]);
        cfg.auth.token_source = Some(TokenSource {
            r#type: "exec".to_string(),
            file_path: None,
            exec,
        });
        apply_token_source(&mut cfg).unwrap();
        assert_eq!(cfg.auth.token.as_deref(), Some("exec-token-9"));
    }

    /// exec 命令非零退出 → 报错
    #[test]
    fn exec_failure_is_error() {
        let mut cfg = base_config();
        cfg.auth.token_source = Some(TokenSource {
            r#type: "exec".to_string(),
            file_path: None,
            exec: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 3".to_string(),
            ]),
        });
        assert!(apply_token_source(&mut cfg).is_err());
    }

    /// 未配置 tokenSource 时保持原样（token 不被改写）
    #[test]
    fn noop_without_token_source() {
        let mut cfg = base_config();
        cfg.auth.token = Some("static".to_string());
        apply_token_source(&mut cfg).unwrap();
        assert_eq!(cfg.auth.token.as_deref(), Some("static"));
    }
}

#[cfg(test)]
mod client_id_tests {
    use crate::*;
    use rust_frp_config::ClientConfig;

    fn cfg_without_client_id() -> ClientConfig {
        ClientConfig {
            client_id: None,
            ..ClientConfig::default()
        }
    }

    /// 未配置 client_id → 随机生成 16 位（不是空、不是主机名）
    #[test]
    fn ensure_client_id_generates_when_absent() {
        let mut cfg = cfg_without_client_id();
        ensure_client_id(&mut cfg, None);
        let id = cfg.client_id.expect("client_id 必须被补齐");
        assert_eq!(id.len(), 16, "应为 rand_id(16) 生成的 16 位随机串");
    }

    /// 已显式配置 → 不被 fallback 覆盖
    #[test]
    fn ensure_client_id_keeps_explicit_value() {
        let mut cfg = ClientConfig {
            client_id: Some("explicit-id".to_string()),
            ..ClientConfig::default()
        };
        ensure_client_id(&mut cfg, Some("inherited-id"));
        assert_eq!(cfg.client_id.as_deref(), Some("explicit-id"));
    }

    /// 回归（2026-10-05 事故）：热重载读到的配置未写 client_id 时必须沿用当前
    /// 生效值 —— 既不能退回 None（登录退化成主机名 → 同名主机互踢），也不能
    /// 重新随机（服务端视作新客户端，与旧会话抢占同名代理）。
    #[test]
    fn ensure_client_id_inherits_current_value_on_reload() {
        let current = "cli32-d2502b0e2ea0f26e".to_string();

        let mut reloaded = cfg_without_client_id();
        ensure_client_id(&mut reloaded, Some(&current));
        assert_eq!(
            reloaded.client_id.as_deref(),
            Some(current.as_str()),
            "热重载后必须沿用当前 client_id"
        );

        // 幂等：连续多次热重载始终是同一个 id
        let mut reloaded2 = cfg_without_client_id();
        ensure_client_id(&mut reloaded2, reloaded.client_id.as_deref());
        assert_eq!(reloaded2.client_id, reloaded.client_id);
    }

    /// fallback 为空串（异常值）不得写回空串，应重新随机
    #[test]
    fn ensure_client_id_ignores_empty_fallback() {
        let mut cfg = cfg_without_client_id();
        ensure_client_id(&mut cfg, Some(""));
        assert_eq!(cfg.client_id.as_deref().map(str::len), Some(16));
    }

    /// 启动与热重载两条路径都不得把 client_id 留空，杜绝退化为主机名
    #[test]
    fn ensure_client_id_never_leaves_empty() {
        let mut startup = cfg_without_client_id();
        ensure_client_id(&mut startup, None);
        assert!(startup.client_id.as_deref().is_some_and(|s| !s.is_empty()));
    }
}

/// STCP visitor 工作端口下传的真实链路测试
///
/// 驱真实 `handle_stcp_visitor_conn` + 真实 `ClientControl` 消息循环 +
/// 真实 frps：服务端配置**自定义工作端口**（≠ server_port+1000），
/// 验证 visitor 腿与代理腿都拨 LoginResp 下发的端口，而不是按
/// `server_port + 1000` 推算（推算值所在端口无监听 ⇒ 拨错即快速
/// ECONNREFUSED，测试立即失败而非挂到超时）。
#[cfg(test)]
mod visitor_work_port_tests {
    use crate::*;
    use rust_frp_config::{AuthConfig, ProxyConfig, ServerConfig, VisitorConfig};
    use std::time::Duration;

    /// 串行化本模块的起服测试：各自 spawn 完整 frps，并行会互相抢调度、
    /// 把「等待监听就绪」的重试预算耗穿（Server::new 不 bind，绑定在
    /// start() 里，存在启动窗口）——同 dual_port_e2e 的 SERVER_LOCK。
    static VISITOR_SERVER_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    async fn visitor_server_lock() -> tokio::sync::MutexGuard<'static, ()> {
        VISITOR_SERVER_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    fn free_tcp_port() -> u16 {
        for _ in 0..50 {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp :0");
            let port = l.local_addr().expect("local addr").port();
            if port <= 60_000 {
                return port;
            }
        }
        panic!("no suitable free TCP port found");
    }

    async fn start_echo_server() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo");
        let port = listener.local_addr().expect("echo addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = sock.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stcp_visitor_dials_server_advertised_work_port() {
        let _guard = visitor_server_lock().await;
        let token = "stcp-thread-secret";
        let bind_port = free_tcp_port();
        let work_port = free_tcp_port();
        assert_ne!(
            work_port,
            bind_port + 1000,
            "custom work port must differ from the default for this test to be meaningful"
        );

        // 起 frps：自定义工作端口（登录时经 LoginResp 下发）
        let server_cfg = ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            bind_port,
            work_conn_port: Some(work_port),
            allow_ports: vec![rust_frp_config::PortRange {
                single: None,
                start: Some(10000),
                end: Some(65535),
            }],
            auth: AuthConfig {
                method: "token".to_string(),
                token: Some(token.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut server = rust_frp_server::Server::new(server_cfg, None)
            .await
            .expect("server construct");
        tokio::spawn(async move {
            let _ = server.start().await;
        });

        let echo_port = start_echo_server().await;

        // 客户端配置：stcp 代理（本地服务指向 echo）+ stcp visitor，双方同 secret_key
        let visitor_bind = free_tcp_port();
        let cfg = Arc::new(ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: bind_port,
            client_id: Some("stcp-thread-client".to_string()),
            auth: AuthConfig {
                method: "token".to_string(),
                token: Some(token.to_string()),
                ..Default::default()
            },
            proxies: vec![ProxyConfig {
                name: "stcpx".to_string(),
                r#type: "stcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: echo_port,
                remote_port: None,
                secret_key: Some("stcp-thread-sk".to_string()),
                ..Default::default()
            }],
            visitors: vec![VisitorConfig {
                name: "v-stcpx".to_string(),
                r#type: "stcp".to_string(),
                server_name: "stcpx".to_string(),
                secret_key: Some("stcp-thread-sk".to_string()),
                bind_addr: "127.0.0.1".to_string(),
                bind_port: visitor_bind,
                ..Default::default()
            }],
            ..Default::default()
        });

        // 控制连接：登录 + 注册代理（与 Client::login 同序，此处手驱）
        let mut tcp = None;
        for _ in 0..100 {
            if let Ok(c) = tokio::net::TcpStream::connect(format!("127.0.0.1:{bind_port}")).await {
                tcp = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut tcp = tcp.expect("tcp connect");
        rust_frp_core::write_message(
            &mut tcp,
            &Message::Login(rust_frp_core::LoginMsg {
                arch: std::env::consts::ARCH.to_string(),
                os: std::env::consts::OS.to_string(),
                hostname: "stcp-thread".to_string(),
                pool_count: 1,
                user: String::new(),
                client_id: "stcp-thread-client".to_string(),
                version: "0.1.0".to_string(),
                timestamp: get_timestamp(),
                run_id: "stcp-thread-run".to_string(),
                token: token.to_string(),
                metas: std::collections::HashMap::new(),
                client_spec: None,
            }),
        )
        .await
        .expect("send login");
        let login_resp = tokio::time::timeout(
            Duration::from_secs(5),
            rust_frp_core::read_message(&mut tcp),
        )
        .await
        .expect("login resp within timeout")
        .expect("read login resp");
        let login_resp = match login_resp {
            Message::LoginResp(r) => r,
            other => panic!("expected LoginResp, got {other:?}"),
        };
        assert!(
            login_resp.error.is_empty(),
            "login rejected: {}",
            login_resp.error
        );
        assert_eq!(
            login_resp.work_conn_port, work_port,
            "LoginResp must advertise the custom work conn port"
        );
        let run_id = login_resp.run_id.clone();

        rust_frp_core::write_message(
            &mut tcp,
            &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
                proxy: ProxyConfig {
                    name: "stcpx".to_string(),
                    r#type: "stcp".to_string(),
                    local_ip: "127.0.0.1".to_string(),
                    local_port: echo_port,
                    remote_port: None,
                    secret_key: Some("stcp-thread-sk".to_string()),
                    ..Default::default()
                },
            }),
        )
        .await
        .expect("send register proxy");
        match tokio::time::timeout(
            Duration::from_secs(5),
            rust_frp_core::read_message(&mut tcp),
        )
        .await
        .expect("register resp within timeout")
        .expect("read register resp")
        {
            Message::RegisterProxyResp(r) => {
                assert!(r.error.is_empty(), "register rejected: {}", r.error)
            }
            other => panic!("expected RegisterProxyResp, got {other:?}"),
        }

        // 构造 ClientControl：server_work_conn_port 传登录下发的自定义端口，
        // 消息循环驱动代理侧腿（ReqWorkConn → establish_work_connection → 拨号）
        let auth_manager = Arc::new(AuthManager::new(&cfg.auth).expect("auth manager"));
        let mut control = ClientControl::new(ClientControlDeps {
            conn: ControlConn::new(Box::new(tcp)),
            run_id: run_id.clone(),
            proxy_manager: Arc::new(ClientProxyManager::default()),
            visitor_manager: Arc::new(ClientVisitorManager::default()),
            auth_manager,
            work_conn_manager: Arc::new(WorkConnManager::new()),
            config: Arc::clone(&cfg),
            work_conn_tls: false,
            server_work_conn_port: login_resp.work_conn_port,
            session: None,
        });
        let stcp_tx = control.stcp_visitor_sender();
        let control_run_id = control.run_id.clone();
        let xtcp_registry = control.xtcp_registry();
        let loop_handle = tokio::spawn(async move {
            let _ = control.run().await;
        });

        // visitor 本地连接：自起 listener，accept 到的 sock 作为数据端点
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind endpoint listener");
        let endpoint_port = listener.local_addr().expect("endpoint addr").port();
        let accept_task = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
        let local_conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{endpoint_port}"))
            .await
            .expect("local connect");
        let mut endpoint = accept_task.await.expect("accept join").expect("accept");

        // 直驱 visitor 处理函数（spawn：桥接期间该函数不会返回）
        let cfg_for_visitor = Arc::clone(&cfg);
        let mut visitor_handle = tokio::spawn(async move {
            handle_stcp_visitor_conn(
                local_conn,
                StcpVisitorDeps {
                    bind_addr: format!("127.0.0.1:{visitor_bind}"),
                    proxy_name: "stcpx".to_string(),
                    stcp_tx,
                    run_id: control_run_id,
                    config: cfg_for_visitor,
                    work_conn_tls: false,
                    server_work_conn_port: login_resp.work_conn_port,
                    xtcp_registry,
                },
            )
            .await
        });

        // 数据回环：endpoint → visitor 工作连接 → 桥 → 代理工作连接 → echo → 回程
        // 任一侧提前退出（如 visitor 拨错端口 ECONNREFUSED）立即失败
        let payload: &[u8; 21] = b"visitor-port-threaded";
        let roundtrip = async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            tokio::time::timeout(Duration::from_secs(5), async {
                endpoint.write_all(payload).await.expect("endpoint write");
                endpoint.flush().await.expect("endpoint flush");
                let mut buf = [0u8; 21];
                endpoint
                    .read_exact(&mut buf)
                    .await
                    .expect("endpoint read echo");
                assert_eq!(&buf, payload);
            })
            .await
            .expect("roundtrip within timeout");
        };
        tokio::select! {
            res = &mut visitor_handle => {
                panic!(
                    "stcp visitor exited before data flowed (dialed wrong port?): {:?}",
                    res.expect("visitor join")
                );
            }
            _ = roundtrip => {}
        }

        // 收尾：关端点 → 桥 EOF → visitor 函数应干净返回
        drop(endpoint);
        let visitor_result = tokio::time::timeout(Duration::from_secs(5), &mut visitor_handle)
            .await
            .expect("visitor exit within timeout")
            .expect("visitor join");
        assert!(
            visitor_result.is_ok(),
            "stcp visitor returned error: {:?}",
            visitor_result.err()
        );
        loop_handle.abort();
    }

    async fn start_udp_echo_server() -> u16 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp echo");
        let port = sock.local_addr().expect("udp echo addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
            }
        });
        port
    }

    /// SUDP visitor 会话全链路：自定义工作端口 + 真实 frps + 真实 ClientControl。
    ///
    /// 关键编排：先发 UDP 包让 visitor 会话发起（StcpVisitor 入队待写），
    /// **延迟 300ms 再启动控制循环**——确定性复现「工作连接先于控制消息
    /// 到达服务端」的竞态。修复后 visitor 等 StcpVisitorResp 再拨号，
    /// 循环启动后全链路打通；修复前 visitor 已直拨，桥未建 ⇒ 工作连接被
    /// 池化丢弃，StartWorkConn 永不来 ⇒ 会话超时失败。
    ///
    /// 同时锁死服务端 secret 登记：sudp 代理不登记 secret 时 visitor 会被
    /// fail-closed 拒绝（StcpVisitorResp 带错），本测试同样失败。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sudp_visitor_session_flows_over_custom_work_port() {
        let _guard = visitor_server_lock().await;
        let token = "sudp-thread-secret";
        let bind_port = free_tcp_port();
        let work_port = free_tcp_port();
        assert_ne!(
            work_port,
            bind_port + 1000,
            "custom work port must differ from the default for this test to be meaningful"
        );

        let server_cfg = ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            bind_port,
            work_conn_port: Some(work_port),
            allow_ports: vec![rust_frp_config::PortRange {
                single: None,
                start: Some(10000),
                end: Some(65535),
            }],
            auth: AuthConfig {
                method: "token".to_string(),
                token: Some(token.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut server = rust_frp_server::Server::new(server_cfg, None)
            .await
            .expect("server construct");
        tokio::spawn(async move {
            let _ = server.start().await;
        });

        let udp_echo_port = start_udp_echo_server().await;

        let visitor_bind = free_tcp_port();
        let cfg = Arc::new(ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: bind_port,
            client_id: Some("sudp-thread-client".to_string()),
            auth: AuthConfig {
                method: "token".to_string(),
                token: Some(token.to_string()),
                ..Default::default()
            },
            proxies: vec![ProxyConfig {
                name: "sudpx".to_string(),
                r#type: "sudp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: udp_echo_port,
                remote_port: None,
                secret_key: Some("sudp-thread-sk".to_string()),
                ..Default::default()
            }],
            visitors: vec![VisitorConfig {
                name: "v-sudpx".to_string(),
                r#type: "sudp".to_string(),
                server_name: "sudpx".to_string(),
                secret_key: Some("sudp-thread-sk".to_string()),
                bind_addr: "127.0.0.1".to_string(),
                bind_port: visitor_bind,
                ..Default::default()
            }],
            ..Default::default()
        });

        // 控制连接：登录 + 注册 sudp 代理
        let mut tcp = None;
        for _ in 0..100 {
            if let Ok(c) = tokio::net::TcpStream::connect(format!("127.0.0.1:{bind_port}")).await {
                tcp = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut tcp = tcp.expect("tcp connect");
        rust_frp_core::write_message(
            &mut tcp,
            &Message::Login(rust_frp_core::LoginMsg {
                arch: std::env::consts::ARCH.to_string(),
                os: std::env::consts::OS.to_string(),
                hostname: "sudp-thread".to_string(),
                pool_count: 1,
                user: String::new(),
                client_id: "sudp-thread-client".to_string(),
                version: "0.1.0".to_string(),
                timestamp: get_timestamp(),
                run_id: "sudp-thread-run".to_string(),
                token: token.to_string(),
                metas: std::collections::HashMap::new(),
                client_spec: None,
            }),
        )
        .await
        .expect("send login");
        let login_resp = match tokio::time::timeout(
            Duration::from_secs(5),
            rust_frp_core::read_message(&mut tcp),
        )
        .await
        .expect("login resp within timeout")
        .expect("read login resp")
        {
            Message::LoginResp(r) => r,
            other => panic!("expected LoginResp, got {other:?}"),
        };
        assert!(
            login_resp.error.is_empty(),
            "login rejected: {}",
            login_resp.error
        );
        assert_eq!(
            login_resp.work_conn_port, work_port,
            "LoginResp must advertise the custom work conn port"
        );
        let run_id = login_resp.run_id.clone();

        rust_frp_core::write_message(
            &mut tcp,
            &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
                proxy: ProxyConfig {
                    name: "sudpx".to_string(),
                    r#type: "sudp".to_string(),
                    local_ip: "127.0.0.1".to_string(),
                    local_port: udp_echo_port,
                    remote_port: None,
                    secret_key: Some("sudp-thread-sk".to_string()),
                    ..Default::default()
                },
            }),
        )
        .await
        .expect("send register proxy");
        match tokio::time::timeout(
            Duration::from_secs(5),
            rust_frp_core::read_message(&mut tcp),
        )
        .await
        .expect("register resp within timeout")
        .expect("read register resp")
        {
            Message::RegisterProxyResp(r) => {
                assert!(r.error.is_empty(), "register rejected: {}", r.error)
            }
            other => panic!("expected RegisterProxyResp, got {other:?}"),
        }

        // ClientControl 构造但**先不启动循环**（延迟启动即竞态编排）
        let auth_manager = Arc::new(AuthManager::new(&cfg.auth).expect("auth manager"));
        let mut control = ClientControl::new(ClientControlDeps {
            conn: ControlConn::new(Box::new(tcp)),
            run_id: run_id.clone(),
            proxy_manager: Arc::new(ClientProxyManager::default()),
            visitor_manager: Arc::new(ClientVisitorManager::default()),
            auth_manager,
            work_conn_manager: Arc::new(WorkConnManager::new()),
            config: Arc::clone(&cfg),
            work_conn_tls: false,
            server_work_conn_port: login_resp.work_conn_port,
            session: None,
        });
        let stcp_tx = control.stcp_visitor_sender();

        // 启动 sudp visitor（绑定 UDP 并等待首个包）
        tokio::spawn(start_sudp_visitor(
            format!("127.0.0.1:{visitor_bind}"),
            "sudpx".to_string(),
            stcp_tx,
            run_id,
            Arc::clone(&cfg),
            false,
            login_resp.work_conn_port,
        ));

        // spawn 只代表任务已排队，不代表 UDP bind 已完成；先通过“端口不可再绑”
        // 确认 visitor 已进入 recv 循环，避免首包被无监听端口静默丢弃。
        // 预算 10s：探针自己也可能抢在 visitor 之前绑上端口，导致 visitor 走
        // start_sudp_visitor 里 1s 的重试退避；再叠加全量并行测试的调度延迟，
        // 1s 预算会出现偶发假红（实测 CI 出现过）。
        let visitor_addr = format!("127.0.0.1:{visitor_bind}");
        let mut visitor_ready = false;
        for _ in 0..1000 {
            match tokio::net::UdpSocket::bind(&visitor_addr).await {
                Ok(probe) => drop(probe),
                Err(_) => {
                    visitor_ready = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(visitor_ready, "SUDP visitor did not bind before packet");

        // 发包触发会话建立（此时 StcpVisitor 仅入队，控制循环未启动）
        let my_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind my udp");
        let payload: &[u8; 18] = b"sudp-port-threaded";
        my_sock
            .send_to(payload, &visitor_addr)
            .await
            .expect("send udp");

        // 竞态窗口：修复前 visitor 在此已直拨工作端口（桥未建 ⇒ 被丢弃）；
        // 修复后 visitor 阻塞等待 StcpVisitorResp
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 启动控制循环：StcpVisitor 写出 → 服务端建桥 + ReqWorkConn（代理腿）+
        // StcpVisitorResp（唤醒 visitor 腿）
        let loop_handle = tokio::spawn(async move {
            let _ = control.run().await;
        });

        // 回环：my_sock → visitor 腿 → 桥 → 代理腿 → UDP echo → 原路返回
        let mut buf = [0u8; 18];
        // 产品 visitor 响应预算为 10s；测试窗口必须覆盖该预算并留出
        // 全量 workspace 并行执行时的调度余量，避免把正常等待判成死锁。
        let (n, _) = tokio::time::timeout(Duration::from_secs(15), my_sock.recv_from(&mut buf))
            .await
            .expect("sudp echo within timeout (visitor leg dialed before bridge ready?)")
            .expect("recv udp echo");
        assert_eq!(&buf[..n], payload, "udp payload mismatch");

        loop_handle.abort();
    }
}

#[cfg(test)]
mod stcp_waiter_registry_tests {
    //! P1-1 回归：等待方消失后不得在全局表留下 dead sender。
    //! 留下 sender 的后果是客户端长跑时内存与每次 resolve 的唤醒耗时单调增长。
    use crate::*;

    #[test]
    fn waiter_dropped_after_abandon_leaves_no_sender() {
        let key = "waiter-leak-regression";
        for _ in 0..5 {
            let waiter = StcpRespRegistry::global().register(key);
            drop(waiter); // 模拟超时/提前返回：等待方消失
        }
        assert_eq!(
            StcpRespRegistry::global().pending_len(key),
            0,
            "等待方消失后必须无残留 sender（否则全局表无界增长）"
        );
    }

    #[tokio::test]
    async fn waiter_clears_entry_after_timeout() {
        let key = "waiter-timeout-regression";
        let waiter = StcpRespRegistry::global().register(key);
        assert_eq!(StcpRespRegistry::global().pending_len(key), 1);
        let r = waiter
            .wait_timeout(std::time::Duration::from_millis(20))
            .await;
        assert!(matches!(r, Err(StcpWaitError::Timeout)), "无应答时应超时");
        assert_eq!(
            StcpRespRegistry::global().pending_len(key),
            0,
            "超时后必须自动反注册"
        );
    }

    #[tokio::test]
    async fn resolve_wakes_waiter_and_clears_entry() {
        let key = "waiter-resolve-regression";
        let waiter = StcpRespRegistry::global().register(key);
        let grant = StcpVisitorGrant {
            bridge_id: key.to_string(),
            work_conn_sign_key: "work-key".to_string(),
        };
        StcpRespRegistry::global().resolve(key, Ok(grant.clone()));
        let r = waiter.wait_timeout(std::time::Duration::from_secs(1)).await;
        assert!(matches!(r, Ok(Ok(v)) if v == grant), "应收到服务端确认");
        assert_eq!(
            StcpRespRegistry::global().pending_len(key),
            0,
            "resolve 后不应残留"
        );
    }

    #[tokio::test]
    async fn bridge_responses_do_not_wake_other_connections() {
        let key1 = "bridge-response-1";
        let key2 = "bridge-response-2";
        let waiter1 = StcpRespRegistry::global().register(key1);
        let waiter2 = StcpRespRegistry::global().register(key2);
        let grant = StcpVisitorGrant {
            bridge_id: key1.to_string(),
            work_conn_sign_key: "work-key-1".to_string(),
        };
        StcpRespRegistry::global().resolve(key1, Ok(grant.clone()));
        assert_eq!(
            waiter1
                .wait_timeout(std::time::Duration::from_secs(1))
                .await
                .expect("wait key1")
                .expect("grant key1"),
            grant
        );
        assert_eq!(
            StcpRespRegistry::global().pending_len(key2),
            1,
            "bridge 1 response must not wake bridge 2"
        );
        drop(waiter2);
    }
}

#[cfg(test)]
mod work_conn_error_tests {
    use crate::work_conn_disconnect_is_retryable;

    #[test]
    fn recycled_pool_eof_is_retryable() {
        for message in [
            "peer closed connection without sending TLS close_notify",
            "Custom { kind: UnexpectedEof, error: \"early eof\" }",
            "connection reset by peer",
            "Broken pipe",
        ] {
            assert!(
                work_conn_disconnect_is_retryable(message),
                "expected transient disconnect for {message}"
            );
        }
    }

    #[test]
    fn authentication_and_configuration_errors_stay_visible() {
        for message in [
            "Server error: Sign key mismatch",
            "Proxy config not found: web_app",
            "use_encryption requires a configured token",
        ] {
            assert!(
                !work_conn_disconnect_is_retryable(message),
                "non-transient error must remain ERROR: {message}"
            );
        }
    }
}
