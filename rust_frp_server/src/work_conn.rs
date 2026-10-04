//! 工作连接管理：连接池、管理器与首字节分类

use rust_frp_core::Message;
use rust_frp_net::AnyConn;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, RwLock};

use crate::*;

/// 工作连接管理器
pub struct WorkConnManager {
    /// 等待工作连接的通道 (proxy_name, sender)
    pending_conns: RwLock<std::collections::HashMap<String, mpsc::Sender<tokio::net::TcpStream>>>,
}

impl Default for WorkConnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkConnManager {
    pub fn new() -> Self {
        Self {
            pending_conns: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册一个等待工作连接的请求
    pub async fn register_pending(
        &self,
        proxy_name: String,
    ) -> mpsc::Receiver<tokio::net::TcpStream> {
        let (tx, rx) = mpsc::channel::<tokio::net::TcpStream>(1);
        let mut pending = self.pending_conns.write().await;
        pending.insert(proxy_name, tx);
        rx
    }

    /// 完成一个工作连接
    pub async fn complete_work_conn(
        &self,
        proxy_name: &str,
        work_conn: tokio::net::TcpStream,
    ) -> Result<(), String> {
        let pending = self.pending_conns.read().await;
        if let Some(sender) = pending.get(proxy_name) {
            sender
                .send(work_conn)
                .await
                .map_err(|e| format!("Failed to send work conn: {}", e))?;
            Ok(())
        } else {
            Err(format!(
                "No pending work conn request for proxy: {}",
                proxy_name
            ))
        }
    }
}

/// 服务器工作连接管理器（池模式）
/// 参考 frp 原版设计：预建工作连接池，访客到达时从池中取用。
/// 无 per-request 状态，自然杜绝僵尸条目和内存泄漏。
pub struct ServerWorkConnManager {
    /// 工作连接池 (proxy_name -> pool)
    pools: RwLock<std::collections::HashMap<String, Arc<WorkConnPool>>>,
    /// 每个代理的池大小
    pool_size: usize,
}

/// 单个代理的工作连接池
pub(crate) struct WorkConnPool {
    tx: mpsc::Sender<AnyConn>,
    rx: tokio::sync::Mutex<mpsc::Receiver<AnyConn>>,
}

impl Default for ServerWorkConnManager {
    fn default() -> Self {
        Self::new(10)
    }
}

impl ServerWorkConnManager {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pools: RwLock::new(std::collections::HashMap::new()),
            pool_size,
        }
    }

    /// 为代理初始化工作连接池
    pub async fn init_pool(&self, proxy_name: &str) {
        let (tx, rx) = mpsc::channel::<AnyConn>(self.pool_size);
        let pool = Arc::new(WorkConnPool {
            tx,
            rx: tokio::sync::Mutex::new(rx),
        });
        let mut pools = self.pools.write().await;
        pools.insert(proxy_name.to_string(), pool);
        log::info!(
            "Initialized work conn pool for proxy: {}, capacity: {}",
            proxy_name,
            self.pool_size
        );
    }

    /// 注册工作连接到池中（由 process_work_conn 调用）
    /// 如果池已满，连接将被丢弃并关闭（背压保护）
    pub async fn register_work_conn(&self, proxy_name: &str, mut conn: AnyConn) {
        global_metrics().incr_work_conn_total();
        let pools = self.pools.read().await;
        if let Some(pool) = pools.get(proxy_name) {
            match pool.tx.try_send(conn) {
                Ok(_) => log::debug!("Work conn registered in pool for {}", proxy_name),
                Err(mpsc::error::TrySendError::Full(mut conn)) => {
                    log::warn!(
                        "Work conn pool full for {}, discarding and closing",
                        proxy_name
                    );
                    let _ = conn.shutdown().await;
                }
                Err(mpsc::error::TrySendError::Closed(mut conn)) => {
                    log::debug!(
                        "Work conn pool closed for {}, closing connection",
                        proxy_name
                    );
                    let _ = conn.shutdown().await;
                }
            }
        } else {
            log::warn!(
                "No pool initialized for proxy: {}, discarding and closing work conn",
                proxy_name
            );
            let _ = conn.shutdown().await;
        }
    }

    /// 获取工作连接（供 TCP/HTTP/HTTPS/WebSocket 处理器调用）
    /// 与 frp 原版一致：从池中取 → 发 StartWorkConn，失败则重试 pool_size+1 次，
    /// 成功后立即补充一个请求保持池始终有可用连接。
    pub async fn get_work_conn(
        &self,
        proxy_name: &str,
        msg_tx: &tokio::sync::mpsc::Sender<Message>,
        timeout: Duration,
        visitor_addr: std::net::SocketAddr,
    ) -> Result<AnyConn, String> {
        // 获取代理的池（克隆 Arc，避免生命周期问题）
        let pool: Arc<WorkConnPool> = {
            let pools = self.pools.read().await;
            pools
                .get(proxy_name)
                .ok_or_else(|| format!("Pool not found for proxy: {}", proxy_name))?
                .clone()
        };

        let max_retries = self.pool_size + 1;
        let mut last_err = String::new();

        for retry in 0..max_retries {
            // 1. 从池中获取连接（池空则请求+等待）
            let mut conn = {
                let mut rx = pool.rx.lock().await;
                match rx.try_recv() {
                    Ok(c) => c,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        drop(rx);
                        log::debug!(
                            "Pool empty for {}, requesting new work conn (retry {}/{})",
                            proxy_name,
                            retry + 1,
                            max_retries
                        );
                        let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                            proxy_name: proxy_name.to_string(),
                        });
                        msg_tx
                            .send(req)
                            .await
                            .map_err(|e| format!("Failed to send ReqWorkConn: {}", e))?;

                        let mut rx = pool.rx.lock().await;
                        match tokio::time::timeout(timeout, rx.recv()).await {
                            Ok(Some(c)) => c,
                            Ok(None) => return Err("Pool channel closed".to_string()),
                            Err(_) => {
                                return Err(format!(
                                    "Timeout waiting for work conn for {}",
                                    proxy_name
                                ))
                            }
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err("Pool disconnected".to_string());
                    }
                }
            };

            // 2. 发送 StartWorkConn 唤醒客户端（携带访问者地址，用于 PROXY protocol）
            let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                error: "".to_string(),
                src_addr: visitor_addr.ip().to_string(),
                src_port: visitor_addr.port(),
                dst_addr: "127.0.0.1".to_string(),
                dst_port: 0,
            });
            match rust_frp_core::write_message(&mut conn, &resp).await {
                Ok(_) => {
                    // 成功后立即补充，保持池始终有可用连接（与 frp 原版一致）
                    let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                        proxy_name: proxy_name.to_string(),
                    });
                    let _ = msg_tx.try_send(req);
                    return Ok(conn);
                }
                Err(e) => {
                    last_err = format!("Failed to send StartWorkConn: {}", e);
                    log::warn!(
                        "{} for proxy {} (retry {}/{})",
                        last_err,
                        proxy_name,
                        retry + 1,
                        max_retries
                    );
                    // 连接已损坏，丢弃，继续重试
                    drop(conn);
                }
            }
        }

        Err(format!(
            "All {} retries exhausted for {}: {}",
            max_retries, proxy_name, last_err
        ))
    }

    /// 移除代理的池（代理停止时调用）
    pub async fn remove_pool(&self, proxy_name: &str) {
        let mut pools = self.pools.write().await;
        pools.remove(proxy_name);
        log::info!("Removed work conn pool for {}", proxy_name);
    }
}

/// 工作连接首字节分类结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkConnClass {
    /// 客户端发起 TLS 握手（首字节 0x16）且服务器已配置 TLS
    Tls,
    /// 明文协议（兼容旧客户端）
    Plain,
    /// 拒绝连接
    Reject,
}

/// 根据首字节判定工作连接处理方式
///
/// - `first_byte == 0x16`：TLS ClientHello，服务器配置了 TLS 则走 TLS，
///   未配置则无法完成握手只能拒绝
/// - 其他字节：明文协议；tls_only 模式下拒绝（防止降级）
pub fn classify_work_conn(first_byte: u8, tls_available: bool, tls_only: bool) -> WorkConnClass {
    match (first_byte == 0x16, tls_available, tls_only) {
        (true, true, _) => WorkConnClass::Tls,
        (true, false, _) => WorkConnClass::Reject,
        (false, _, true) => WorkConnClass::Reject,
        (false, _, false) => WorkConnClass::Plain,
    }
}

/// 工作连接错误日志（对端断开类错误降级为 debug，避免日志噪音）
pub(crate) fn log_work_conn_error(e: &(dyn std::error::Error + Send + Sync)) {
    let msg = e.to_string().to_lowercase();
    if msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("broken pipe")
    {
        log::debug!("Work connection closed (peer disconnected): {:?}", e);
    } else {
        log::error!("Failed to process work connection: {:?}", e);
    }
}
