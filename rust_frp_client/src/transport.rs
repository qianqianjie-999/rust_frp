//! 从 lib.rs 拆出的 transport 实现。

use super::*;

/// 从配置提取客户端证书（mTLS：出示给服务端校验）
///
/// 只配一半（有证书无私钥）无法出示证书，握手必失败 ⇒ 直接报错。配置层已拦，这里
/// 再兜一层，防止绕过配置校验的调用方（如管理端 `PUT /config`）。
pub(super) fn client_cert_of(
    tls: &rust_frp_config::TlsConfig,
) -> Result<Option<(&str, &str)>, Box<dyn std::error::Error>> {
    match (&tls.cert_file, &tls.key_file) {
        (Some(c), Some(k)) => Ok(Some((c.as_str(), k.as_str()))),
        (None, None) => Ok(None),
        _ => Err(
            "transport.tls.cert_file and transport.tls.key_file must be configured together \
             (they carry the client certificate presented for mTLS)"
                .into(),
        ),
    }
}

/// 构建客户端 TLS 配置（供控制连接与工作连接复用）
///
/// - 配置了 `trusted_ca_file` → 用该 CA 验证服务器证书（推荐）；
///   若同时配了 `cert_file`/`key_file` ⇒ **mTLS**：双向认证
/// - `trusted_ca_file` 未配置且 `skip_verify = true` → 跳过证书验证（仅加密，不认证）
/// - `trusted_ca_file` 未配置且 `skip_verify = false`（默认）→ **报错拒绝启动**（fail-closed），
///   避免在用户不知情时静默退化为"只加密不认证"
///
/// # ⚠️ 安全提示
///
/// `skip_verify = true` 意味着任何中间人都可以冒充服务端，仅应在测试环境使用。
/// 生产环境请务必配置 `transport.tls.trusted_ca_file`，并在服务端换用自建证书。
///
/// # ⚠️ mTLS 的两个方向
///
/// 两个方向互不相同、都不可省：`trusted_ca_file` 管"我验服务端"，`cert_file`/`key_file`
/// 管"服务端验我"。**出示证书却不校验服务端**等于把身份递给可能冒充服务端的中间人，
/// 因此本函数（及配置校验）拒绝 `cert_file` + `skip_verify = true` 的组合。
///
/// # ⚠️ `trusted_ca_file` 的生效前提
///
/// `trusted_ca_file` 是在**服务端证书稳定且 SAN 与 `server_addr` 匹配**时才有效：
/// 校验同时包含"链是否被该 CA 签发"与"证书名是否匹配 `server_addr`"。
/// 若服务端未配 `cert_file`/`key_file`，将使用**内置运行时自签证书**——它每次重启
/// 重新生成、SAN 仅含 `frp-server.local`/`localhost`，因此**无法**被 `trusted_ca_file` 固定
/// （即使拿到证书，连 IP 时也会因名称不匹配失败）。这种场景只有两条路：
/// 服务端改用 SAN 匹配的自建证书，或客户端显式 `skip_verify = true`。
pub(super) fn build_client_tls_config(
    config: &rust_frp_config::ClientConfig,
) -> Result<Option<TlsConfig>, Box<dyn std::error::Error>> {
    let Some(tls) = &config.transport.tls else {
        return Ok(None);
    };
    if !tls.enable {
        return Ok(None);
    }
    let client_cert = client_cert_of(tls)?;

    if let Some(ref ca_file) = tls.trusted_ca_file {
        return Ok(Some(match client_cert {
            Some((cert_file, key_file)) => {
                TlsConfig::new_client_with_ca_and_cert(ca_file, cert_file, key_file)?
            }
            None => TlsConfig::new_client_with_ca_file(ca_file)?,
        }));
    }
    if tls.skip_verify {
        if client_cert.is_some() {
            return Err(
                "transport.tls.skip_verify = true cannot be combined with a client certificate \
                 (cert_file/key_file): skipping server verification would let an impostor server \
                 collect the client certificate. Remove skip_verify and set trusted_ca_file \
                 (fail-closed)."
                    .into(),
            );
        }
        log::warn!(
            "TLS enabled with transport.tls.skip_verify = true: the server certificate \
             will NOT be verified. This provides encryption only, NOT authentication."
        );
        return Ok(Some(TlsConfig::new_client_insecure()?));
    }
    Err(
        "TLS is enabled but transport.tls.trusted_ca_file is not set and \
         transport.tls.skip_verify is false: refusing to connect with unverified server \
         certificate (fail-closed). Set trusted_ca_file to pin the server CA (the server must \
         present a stable cert whose SAN matches server_addr; the built-in runtime self-signed \
         cert is regenerated every restart and only carries 'frp-server.local'/'localhost', so \
         it cannot be pinned), or set skip_verify = true to explicitly accept the risk \
         (encryption only, no authentication)."
            .into(),
    )
}

/// 计算服务器工作连接端口（frps.toml 的 work_conn_port，默认 server_port + 1000）
pub(super) fn work_conn_port_of(config: &rust_frp_config::ClientConfig) -> u16 {
    config.work_conn_port.unwrap_or(config.server_port + 1000)
}

/// 解析工作连接端口：服务器 LoginResp 下发值 > 客户端配置 > server_port + 1000
///
/// 服务器通过 `LoginRespMsg.work_conn_port` 下发真实端口（0 = 旧版服务端未下发），
/// 避免"服务端自定义了 work_conn_port 而客户端按默认值推算"的错位。
pub(super) fn resolve_work_conn_port(
    config: &rust_frp_config::ClientConfig,
    server_work_conn_port: u16,
) -> u16 {
    if server_work_conn_port > 0 {
        server_work_conn_port
    } else {
        work_conn_port_of(config)
    }
}

/// 工作端口最近一次直拨失败的时间（Unix 秒；0 = 从未失败）
///
/// `transport.work_conn_via = "auto"` 时的降级记忆：直拨失败（典型为安全组/防火墙
/// 未放行工作端口）后 60 秒内不再尝试直拨，避免每次建工作连接都白等超时；
/// 60 秒后重试一次，网络恢复（如端口放行）后自动回到数据/控制分离路径。
pub(super) static WORK_PORT_LAST_FAIL_SECS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

pub(super) const WORK_PORT_RETRY_INTERVAL_SECS: i64 = 60;

/// 出站 TCP 复用缓存的大小（`ConnManager` 内部池）
///
/// 与 `transport.pool_count`（预建工作连接数，默认 0）**无关**：那个值是
/// 「为代理提前准备多少条工作连接」，这里是「客户端拨号时复用多少条底层
/// TCP」。两者共用一个数值会让 `pool_count = 0` 把信号量初始化为 0，
/// 进而把 `get()` 永久阻塞。
pub(super) const CONN_REUSE_POOL_SIZE: usize = 10;

pub(super) fn work_port_currently_preferred() -> bool {
    let last = WORK_PORT_LAST_FAIL_SECS.load(std::sync::atomic::Ordering::Relaxed);
    if last == 0 {
        return true;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    now - last >= WORK_PORT_RETRY_INTERVAL_SECS
}

pub(super) fn mark_work_port_failed() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    WORK_PORT_LAST_FAIL_SECS.store(now, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn mark_work_port_ok() {
    WORK_PORT_LAST_FAIL_SECS.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// 解析服务器地址为 `SocketAddr`（支持 IP 字面量与域名）
pub(super) async fn resolve_server_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("failed to resolve {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address resolved for {host}:{port}"))
}

/// 由 `transport.quic` 构造 QUIC 传输参数（未配置时用与原版 frp 一致的默认值）
pub(super) fn quic_options(config: &rust_frp_config::ClientConfig) -> rust_frp_net::QuicOptions {
    let q = config.transport.quic.as_ref();
    rust_frp_net::QuicOptions::from_config(
        q.and_then(|q| q.max_idle_timeout),
        q.and_then(|q| q.max_incoming_streams),
        q.and_then(|q| q.keepalive_period),
    )
}

/// 客户端连接器
pub struct Connector {
    config: Arc<rust_frp_config::ClientConfig>,
    conn_manager: ConnManager,
}

impl Connector {
    pub fn new(
        config: Arc<rust_frp_config::ClientConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tls_config = build_client_tls_config(&config)?;

        // 注意：这里的「连接池」是**出站 TCP 复用缓存**，与 `transport.pool_count`
        // （预建工作连接数）是两件事。历史上两者共用同一个数值，导致
        // `pool_count = 0` 会把这里的信号量初始化为 0，`get()` 永久阻塞。
        // 现按语义拆开：复用缓存固定用 CONN_REUSE_POOL_SIZE。
        let conn_manager = ConnManager::new(tls_config, CONN_REUSE_POOL_SIZE);

        Ok(Self {
            config,
            conn_manager,
        })
    }

    pub async fn connect(
        &mut self,
    ) -> Result<rust_frp_net::PooledConn, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tcp(&addr).await?)
    }

    pub async fn connect_tls(
        &mut self,
        domain: &str,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error>>
    {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tls(domain, &addr).await?)
    }

    pub async fn connect_kcp(
        &mut self,
    ) -> Result<rust_frp_net::KcpConn, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_kcp(&addr).await?)
    }

    /// 建立到服务端的 QUIC 连接（控制连接与工作连接复用同一 QUIC 连接）
    ///
    /// QUIC 强制 TLS 1.3，无明文模式：证书校验沿用 `transport.tls` 的
    /// fail-closed 语义（`trusted_ca_file` 认证，或显式 `skip_verify = true`）。
    pub async fn connect_quic(
        &mut self,
    ) -> Result<Arc<rust_frp_net::QuicSession>, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        let tls = self.config.transport.tls.as_ref();
        let ca = tls.and_then(|t| t.trusted_ca_file.as_deref());
        let insecure = tls.map(|t| t.skip_verify).unwrap_or(false);
        // mTLS：出示客户端证书（配置层已保证 cert/key 成对、且不与 skip_verify 同现）
        let client_cert = tls.and_then(|t| match (&t.cert_file, &t.key_file) {
            (Some(c), Some(k)) => Some((c.as_str(), k.as_str())),
            _ => None,
        });
        let opts = quic_options(&self.config);
        let cfg = rust_frp_net::build_quic_client_config(ca, insecure, client_cert, &opts)
            .map_err(|e| {
                format!(
                    "QUIC always uses TLS 1.3 and has no plaintext mode: {e}. \
                 Set transport.tls.trusted_ca_file to pin the server CA, or \
                 transport.tls.skip_verify = true to accept encryption without authentication"
                )
            })?;
        let session =
            rust_frp_net::QuicSession::connect(addr, &self.config.server_addr, cfg).await?;
        Ok(Arc::new(session))
    }
}

/// XTCP 打洞会话注册表
///
/// visitor 侧每个等待打洞的本地连接注册一个 oneshot 通道；
/// 当 owner 回传的 `XtcpNatInfo` 经服务器中继到达时，按 proxy_name
/// 唤醒等待中的连接任务，携带 owner 的公网/本地地址。
///
/// 单槽语义：协议按 proxy_name 路由 NatInfo（无连接级 ID），
/// 同 proxy 同时只允许一个打洞会话；新会话注册时替换旧的，
/// 旧等待者 oneshot 关闭后自动回退 STCP 中继。
#[derive(Default)]
pub(super) struct XtcpRegistry {
    /// proxy_name -> 等待 owner 地址的 oneshot
    pending: std::sync::Mutex<
        std::collections::HashMap<String, tokio::sync::oneshot::Sender<(String, String)>>,
    >,
}

impl XtcpRegistry {
    /// 注册一个等待 owner 地址的 visitor 会话，返回接收端。
    /// 同 proxy 已有等待者时替换之（旧接收端收到 RecvError → STCP 回退）。
    pub(super) fn register(
        &self,
        proxy_name: String,
    ) -> tokio::sync::oneshot::Receiver<(String, String)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(proxy_name, tx);
        rx
    }

    /// owner 地址到达时唤醒等待者；返回是否有等待者
    pub(super) fn resolve(&self, proxy_name: &str, addrs: (String, String)) -> bool {
        if let Some(tx) = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(proxy_name)
        {
            let _ = tx.send(addrs);
            true
        } else {
            false
        }
    }
}

/// STCP 访问端应答等待表：proxy_name -> (等待者 id, 等待桥就绪确认的 oneshot) 列表
///
/// 带上 id 是为了**精确反注册**：等待方超时/被拒/发送失败提前返回后必须把自己摘掉。
/// 只 push 不摘会让 dead sender 在全局表里无限累积——客户端长跑时内存与
/// 每次 `resolve` 的唤醒耗时都会单调增长（见 StcpWaiter 的 Drop）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StcpVisitorGrant {
    pub(super) bridge_id: String,
    pub(super) work_conn_sign_key: String,
}

pub(super) type StcpPendingMap = std::collections::HashMap<
    String,
    Vec<(
        u64,
        tokio::sync::oneshot::Sender<Result<StcpVisitorGrant, String>>,
    )>,
>;

/// 等待失败的原因：区分"服务端明确拒绝"与"本地等待异常"，调用方据此给出不同文案
#[derive(Debug)]
pub(super) enum StcpWaitError {
    /// 超过等待时限（桥一直没就绪）
    Timeout,
    /// 等待通道被关闭（控制连接重连等）
    Dropped,
}

/// STCP 访问端应答等待器：handle_stcp_visitor_conn 在发出 StcpVisitor 后
/// 必须等服务端桥就绪确认（StcpVisitorResp）再拨工作连接。否则存在竞态：
/// 工作连接可能先于控制消息被服务端处理，此时桥尚未建立，连接被当作
/// 普通代理工作连接丢弃，visitor 永远等不到 StartWorkConn 而超时。
pub(super) struct StcpRespRegistry {
    /// proxy_name -> 等待桥就绪确认的等待者列表（并发访问同代理时全部唤醒）
    pending: std::sync::Mutex<StcpPendingMap>,
    /// 等待者发号器：id 单调递增，进程内不重复
    next_id: std::sync::atomic::AtomicU64,
}

impl StcpRespRegistry {
    pub(super) fn global() -> &'static Self {
        static REG: std::sync::OnceLock<StcpRespRegistry> = std::sync::OnceLock::new();
        REG.get_or_init(|| StcpRespRegistry {
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// 注册等待者，返回**可自动反注册**的等待句柄（见 `StcpWaiter`）
    pub(super) fn register(&self, bridge_id: &str) -> StcpWaiter {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(bridge_id.to_string())
            .or_default()
            .push((id, tx));
        StcpWaiter {
            bridge_id: bridge_id.to_string(),
            id,
            rx: Some(rx),
        }
    }

    /// 服务端应答到达时只唤醒对应 bridge_id 的等待者。
    pub(super) fn resolve(&self, bridge_id: &str, result: Result<StcpVisitorGrant, String>) {
        if let Some(waiters) = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(bridge_id)
        {
            for (_, tx) in waiters {
                let _ = tx.send(result.clone());
            }
        }
    }

    /// 摘掉单个等待者（由 `StcpWaiter::drop` 触发）；列表空则顺带删掉 key，
    /// 避免留下空 Vec 占住表名。
    pub(super) fn cancel(&self, bridge_id: &str, id: u64) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut now_empty = false;
        if let Some(waiters) = pending.get_mut(bridge_id) {
            waiters.retain(|(wid, _)| *wid != id);
            now_empty = waiters.is_empty();
        }
        if now_empty {
            pending.remove(bridge_id);
        }
    }

    /// 当前仍在等待的 sender 数（测试判据）
    #[cfg(test)]
    pub(super) fn pending_len(&self, proxy_name: &str) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(proxy_name)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

/// 等待句柄：**Drop 即反注册**。
///
/// 这样无论等待方是成功、被拒、超时还是发送失败提前 return，都不会在
/// 全局表里留下 dead sender——把"必须记得清理"从调用方的自觉变成类型系统的保证。
pub(super) struct StcpWaiter {
    bridge_id: String,
    id: u64,
    rx: Option<tokio::sync::oneshot::Receiver<Result<StcpVisitorGrant, String>>>,
}

impl StcpWaiter {
    /// 等待服务端应答；返回后句柄析构，自动反注册。
    pub(super) async fn wait_timeout(
        mut self,
        dur: std::time::Duration,
    ) -> Result<Result<StcpVisitorGrant, String>, StcpWaitError> {
        // let-else 而非 expect：句柄被消费过一次即视为通道已关闭，不引入 panic 点
        let Some(rx) = self.rx.take() else {
            return Err(StcpWaitError::Dropped);
        };
        match tokio::time::timeout(dur, rx).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => Err(StcpWaitError::Dropped),
            Err(_) => Err(StcpWaitError::Timeout),
        }
    }
}

impl Drop for StcpWaiter {
    fn drop(&mut self) {
        StcpRespRegistry::global().cancel(&self.bridge_id, self.id);
    }
}
