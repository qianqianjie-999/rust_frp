//! 连接池模块
//!
//! 该模块实现了 FRP 的连接池功能，用于复用 TCP 连接，减少连接建立的开销。
//!
//! ## 连接池架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      PoolManager                             │
//! │  管理多个地址对应的连接池 (HashMap<SocketAddr, ConnPool>)    │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!              ┌───────────────┼───────────────┐
//!              ▼               ▼               ▼
//!        ┌──────────┐    ┌──────────┐    ┌──────────┐
//!        │ ConnPool │    │ ConnPool │    │ ConnPool │
//!        │ addr:9000│    │ addr:9001│    │ addr:9002│
//!        └──────────┘    └──────────┘    └──────────┘
//!              │
//!              ▼
//!        ┌──────────────────────────┐
//!        │   Vec<PooledConn>        │
//!        │   (空闲连接池)           │
//!        │                          │
//!        │   Semaphore (并发控制)    │
//!        │   PoolStats (统计信息)    │
//!        └──────────────────────────┘
//! ```
//!
//! ## 核心特性
//!
//! 1. **连接复用**：避免频繁建立和关闭 TCP 连接
//! 2. **并发控制**：使用信号量限制每个池的最大连接数
//! 3. **健康检查**：定期检查连接是否仍然有效
//! 4. **自动清理**：移除过期和无效的连接
//! 5. **统计信息**：跟踪连接创建、复用、关闭等指标
//!
//! ## 安全性
//!
//! - 连接超时保护
//! - 最大生命周期限制
//! - 并发访问安全（使用 Mutex/RwLock）

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock, Semaphore};
use log::{debug, info};
use super::FrpConn;

/// 连接池配置
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// 连接池最大大小
    pub max_size: usize,
    /// 连接超时时间
    pub connection_timeout: Duration,
    /// 连接最大空闲时间
    pub max_idle_time: Duration,
    /// 连接最大生命周期
    pub max_lifetime: Duration,
    /// 是否启用健康检查
    pub health_check: bool,
    /// 健康检查间隔
    pub health_check_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10,
            connection_timeout: Duration::from_secs(5),
            max_idle_time: Duration::from_secs(300), // 5分钟
            max_lifetime: Duration::from_secs(3600), // 1小时
            health_check: true,
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// 池化连接包装器
pub struct PooledConn {
    /// 底层 TCP 连接
    pub conn: TcpStream,
    /// 连接创建时间
    pub created_at: Instant,
    /// 最后使用时间
    pub last_used_at: Instant,
    /// 使用次数
    pub use_count: u64,
}

impl PooledConn {
    /// 创建新的池化连接
    ///
    /// # 参数
    ///
    /// * `conn` - TCP 连接
    pub fn new(conn: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            conn,
            created_at: now,
            last_used_at: now,
            use_count: 0,
        }
    }

    /// 检查连接是否过期
    pub fn is_expired(&self, max_idle_time: Duration, max_lifetime: Duration) -> bool {
        let now = Instant::now();
        now.duration_since(self.last_used_at) > max_idle_time
            || now.duration_since(self.created_at) > max_lifetime
    }

    /// 检查连接是否健康
    pub async fn is_healthy(&mut self) -> bool {
        // 尝试读取，如果连接已关闭会返回错误
        match self.conn.try_write(&[]) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
            Err(_) => false,
        }
    }

    /// 标记连接已使用
    pub fn mark_used(&mut self) {
        self.last_used_at = Instant::now();
        self.use_count += 1;
    }
}

impl AsyncRead for PooledConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.conn).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

impl FrpConn for PooledConn {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.conn.peer_addr().ok()
    }
}

/// 连接池
pub struct ConnPool {
    addr: SocketAddr,
    config: PoolConfig,
    connections: Mutex<Vec<PooledConn>>,
    semaphore: Semaphore,
    stats: RwLock<PoolStats>,
}

/// 连接池统计信息
#[derive(Debug, Default)]
pub struct PoolStats {
    /// 总创建连接数
    pub total_created: u64,
    /// 总复用连接数
    pub total_reused: u64,
    /// 总关闭连接数
    pub total_closed: u64,
    /// 总失败连接数
    pub total_failed: u64,
    /// 当前空闲连接数
    pub current_idle: usize,
    /// 当前使用中连接数
    pub current_in_use: usize,
}

impl ConnPool {
    /// 创建新的连接池
    ///
    /// # 参数
    ///
    /// * `addr` - 连接目标地址
    /// * `config` - 连接池配置
    pub fn new(addr: SocketAddr, config: PoolConfig) -> Self {
        let max_size = config.max_size;
        Self {
            addr,
            config,
            connections: Mutex::new(Vec::with_capacity(max_size)),
            semaphore: Semaphore::new(max_size),
            stats: RwLock::new(PoolStats::default()),
        }
    }

    /// 获取连接
    pub async fn get(&self) -> Result<PooledConn, std::io::Error> {
        // 获取许可
        let _permit = self.semaphore.acquire().await.map_err(|e| {
            std::io::Error::other(format!("Failed to acquire semaphore: {}", e))
        })?;

        // 首先尝试从池中获取空闲连接
        let mut connections = self.connections.lock().await;
        
        while let Some(mut conn) = connections.pop() {
            // 检查连接是否过期
            if conn.is_expired(self.config.max_idle_time, self.config.max_lifetime) {
                debug!("Connection expired, closing");
                drop(conn);
                self.update_stats(|s| s.total_closed += 1).await;
                continue;
            }

            // 检查连接是否健康
            if self.config.health_check && !conn.is_healthy().await {
                debug!("Connection unhealthy, closing");
                drop(conn);
                self.update_stats(|s| s.total_closed += 1).await;
                continue;
            }

            // 连接可用
            conn.mark_used();
            self.update_stats(|s| {
                s.total_reused += 1;
                s.current_in_use += 1;
                s.current_idle = connections.len();
            }).await;
            
            debug!("Reusing connection from pool");
            return Ok(conn);
        }

        // 池中没有可用连接，创建新连接
        drop(connections);
        
        info!("Creating new connection to {}", self.addr);
        let stream = tokio::time::timeout(
            self.config.connection_timeout,
            TcpStream::connect(&self.addr)
        ).await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout")
        })??;

        self.update_stats(|s| {
            s.total_created += 1;
            s.current_in_use += 1;
        }).await;

        Ok(PooledConn::new(stream))
    }

    /// 归还连接
    pub async fn put(&self, mut conn: PooledConn) {
        // 检查连接是否健康
        if self.config.health_check && !conn.is_healthy().await {
            debug!("Connection unhealthy, not returning to pool");
            drop(conn);
            self.update_stats(|s| {
                s.total_closed += 1;
                s.current_in_use -= 1;
            }).await;
            return;
        }

        let mut connections = self.connections.lock().await;
        
        // 如果池已满，关闭连接
        if connections.len() >= self.config.max_size {
            debug!("Pool full, closing connection");
            drop(conn);
            self.update_stats(|s| {
                s.total_closed += 1;
                s.current_in_use -= 1;
            }).await;
            return;
        }

        // 归还连接到池
        connections.push(conn);
        self.update_stats(|s| {
            s.current_in_use -= 1;
            s.current_idle = connections.len();
        }).await;
        
        debug!("Connection returned to pool");
    }

    /// 更新统计信息
    async fn update_stats<F>(&self, f: F)
    where
        F: FnOnce(&mut PoolStats),
    {
        let mut stats = self.stats.write().await;
        f(&mut stats);
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> PoolStats {
        let stats = self.stats.read().await;
        PoolStats {
            total_created: stats.total_created,
            total_reused: stats.total_reused,
            total_closed: stats.total_closed,
            total_failed: stats.total_failed,
            current_idle: stats.current_idle,
            current_in_use: stats.current_in_use,
        }
    }

    /// 清理过期连接
    pub async fn cleanup(&self) {
        let mut connections = self.connections.lock().await;
        let before_count = connections.len();
        
        let expired_count = connections.iter().filter(|conn| {
            conn.is_expired(self.config.max_idle_time, self.config.max_lifetime)
        }).count();
        
        connections.retain(|conn| {
            !conn.is_expired(self.config.max_idle_time, self.config.max_lifetime)
        });

        let after_count = connections.len();
        if before_count != after_count {
            info!("Cleaned up {} expired connections", before_count - after_count);
            drop(connections);
            self.update_stats(|s| {
                s.total_closed += expired_count as u64;
                s.current_idle = after_count;
            }).await;
        }
    }

    /// 关闭所有连接
    pub async fn close_all(&self) {
        let mut connections = self.connections.lock().await;
        let count = connections.len();
        connections.clear();
        
        self.update_stats(|s| {
            s.total_closed += count as u64;
            s.current_idle = 0;
        }).await;
        
        info!("Closed all {} connections in pool", count);
    }
}

/// 连接池管理器
pub struct PoolManager {
    pools: RwLock<std::collections::HashMap<SocketAddr, Arc<ConnPool>>>,
    default_config: PoolConfig,
}

impl PoolManager {
    /// 创建新的连接池管理器
    ///
    /// # 参数
    ///
    /// * `default_config` - 默认连接池配置
    pub fn new(default_config: PoolConfig) -> Self {
        Self {
            pools: RwLock::new(std::collections::HashMap::new()),
            default_config,
        }
    }

    /// 获取或创建连接池
    pub async fn get_or_create_pool(&self, addr: SocketAddr) -> Arc<ConnPool> {
        let pools = self.pools.read().await;
        if let Some(pool) = pools.get(&addr) {
            return pool.clone();
        }
        drop(pools);

        let mut pools = self.pools.write().await;
        // 双重检查
        if let Some(pool) = pools.get(&addr) {
            return pool.clone();
        }

        let pool = Arc::new(ConnPool::new(addr, self.default_config.clone()));
        pools.insert(addr, pool.clone());
        info!("Created new connection pool for {}", addr);
        
        pool
    }

    /// 获取连接池
    pub async fn get_pool(&self, addr: SocketAddr) -> Option<Arc<ConnPool>> {
        let pools = self.pools.read().await;
        pools.get(&addr).cloned()
    }

    /// 移除连接池
    pub async fn remove_pool(&self, addr: SocketAddr) {
        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.remove(&addr) {
            pool.close_all().await;
            info!("Removed connection pool for {}", addr);
        }
    }

    /// 清理所有过期连接
    pub async fn cleanup_all(&self) {
        let pools = self.pools.read().await;
        for (_addr, pool) in pools.iter() {
            pool.cleanup().await;
        }
    }

    /// 获取所有统计信息
    pub async fn get_all_stats(&self) -> std::collections::HashMap<SocketAddr, PoolStats> {
        let pools = self.pools.read().await;
        let mut stats = std::collections::HashMap::new();
        for (addr, pool) in pools.iter() {
            stats.insert(*addr, pool.get_stats().await);
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_size, 10);
        assert_eq!(config.connection_timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_pooled_conn_expired() {
        // 创建一个临时 TCP 监听器
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // 在后台接受连接
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        
        // 连接到这个端口
        let tokio_conn = TcpStream::connect(addr).await.unwrap();
        let conn = PooledConn::new(tokio_conn);
        
        // 新连接不应该过期
        assert!(!conn.is_expired(Duration::from_secs(60), Duration::from_secs(3600)));
        
        // 测试过期检测 - 使用极短的过期时间
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(conn.is_expired(Duration::from_millis(5), Duration::from_secs(3600)));
    }
}
