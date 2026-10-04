//! 监控指标：代理统计、连接守卫与全局单例

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub struct ProxyStat {
    pub name: String,
    pub proxy_type: String,
    pub remote_port: Option<u16>,
    pub current_conns: AtomicUsize,
    pub total_conns: AtomicUsize,
    /// 入口方向累计字节（访问者 → 工作连接，即客户端视角的上行）
    pub bytes_in: AtomicUsize,
    /// 出口方向累计字节（工作连接 → 访问者）
    pub bytes_out: AtomicUsize,
}

impl ProxyStat {
    fn new(name: &str, proxy_type: &str, remote_port: Option<u16>) -> Self {
        Self {
            name: name.to_string(),
            proxy_type: proxy_type.to_string(),
            remote_port,
            current_conns: AtomicUsize::new(0),
            total_conns: AtomicUsize::new(0),
            bytes_in: AtomicUsize::new(0),
            bytes_out: AtomicUsize::new(0),
        }
    }

    /// 累加一次转发流量（桥接结束后调用）
    pub fn add_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.fetch_add(bytes_in as usize, Ordering::SeqCst);
        self.bytes_out
            .fetch_add(bytes_out as usize, Ordering::SeqCst);
    }
}

/// 代理连接统计守卫：创建时 current/total +1，drop 时 current -1，
/// 覆盖任务内所有 return 路径
pub struct ProxyConnGuard {
    stat: std::sync::Arc<ProxyStat>,
}

impl ProxyConnGuard {
    pub fn acquire(stat: std::sync::Arc<ProxyStat>) -> Self {
        stat.total_conns.fetch_add(1, Ordering::SeqCst);
        stat.current_conns.fetch_add(1, Ordering::SeqCst);
        Self { stat }
    }
}

impl Drop for ProxyConnGuard {
    fn drop(&mut self) {
        self.stat.current_conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 监控指标
pub struct MonitorMetrics {
    total_connections: AtomicUsize,
    current_connections: AtomicUsize,
    total_proxies: AtomicUsize,
    current_proxies: AtomicUsize,
    bytes_sent: AtomicUsize,
    bytes_received: AtomicUsize,
    start_time: Instant,
    /// 登录失败累计
    login_failures: AtomicUsize,
    /// 登录成功累计
    login_successes: AtomicUsize,
    /// TLS 握手拒绝累计（tls_only / 非法客户端）
    tls_rejects: AtomicUsize,
    /// 工作连接注册累计
    work_conn_total: AtomicUsize,
    /// per-proxy 统计表（proxy_name -> 指标）
    proxy_stats: std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<ProxyStat>>>,
}

impl Default for MonitorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicUsize::new(0),
            current_connections: AtomicUsize::new(0),
            total_proxies: AtomicUsize::new(0),
            current_proxies: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_received: AtomicUsize::new(0),
            start_time: Instant::now(),
            login_failures: AtomicUsize::new(0),
            login_successes: AtomicUsize::new(0),
            tls_rejects: AtomicUsize::new(0),
            work_conn_total: AtomicUsize::new(0),
            proxy_stats: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn increment_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::SeqCst);
        self.current_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_connections(&self) {
        self.current_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn increment_proxies(&self) {
        self.total_proxies.fetch_add(1, Ordering::SeqCst);
        self.current_proxies.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_proxies(&self) {
        self.current_proxies.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn add_bytes_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn add_bytes_received(&self, bytes: usize) {
        self.bytes_received.fetch_add(bytes, Ordering::SeqCst);
    }

    /// 记录一次代理转发的双向流量（全局计数 + per-proxy 计数）。
    ///
    /// 方向语义：`bytes_in` = 访问者 → 工作连接（入方向），
    /// `bytes_out` = 工作连接 → 访问者（出方向）；与全局
    /// `bytes_received` / `bytes_sent` 对应。代理未注册时仅累加全局计数。
    pub fn record_traffic(&self, proxy_name: &str, bytes_in: u64, bytes_out: u64) {
        self.add_bytes_received(bytes_in as usize);
        self.add_bytes_sent(bytes_out as usize);
        if let Some(stat) = self.get_proxy_stat(proxy_name) {
            stat.add_bytes(bytes_in, bytes_out);
        }
    }

    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_metrics(&self) -> serde_json::Value {
        serde_json::json! {
            {
                "uptime": self.uptime().as_secs(),
                "total_connections": self.total_connections.load(Ordering::SeqCst),
                "current_connections": self.current_connections.load(Ordering::SeqCst),
                "total_proxies": self.total_proxies.load(Ordering::SeqCst),
                "current_proxies": self.current_proxies.load(Ordering::SeqCst),
                "bytes_sent": self.bytes_sent.load(Ordering::SeqCst),
                "bytes_received": self.bytes_received.load(Ordering::SeqCst),
            }
        }
    }

    pub fn incr_login_failures(&self) {
        self.login_failures.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_login_successes(&self) {
        self.login_successes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_tls_rejects(&self) {
        self.tls_rejects.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_work_conn_total(&self) {
        self.work_conn_total.fetch_add(1, Ordering::SeqCst);
    }

    /// 代理注册成功时创建 per-proxy 统计
    pub fn register_proxy_stat(
        &self,
        name: &str,
        proxy_type: &str,
        remote_port: Option<u16>,
    ) -> std::sync::Arc<ProxyStat> {
        let stat = std::sync::Arc::new(ProxyStat::new(name, proxy_type, remote_port));
        self.proxy_stats
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_string(), stat.clone());
        stat
    }

    /// 代理注销时移除统计
    pub fn remove_proxy_stat(&self, name: &str) {
        self.proxy_stats
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(name);
    }

    /// 获取代理统计（用于连接计数守卫）
    pub fn get_proxy_stat(&self, name: &str) -> Option<std::sync::Arc<ProxyStat>> {
        self.proxy_stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// 输出 Prometheus text exposition format (v0.0.4)。
    /// 手写实现，零第三方依赖；label 值做转义防止注入。
    ///
    /// 说明：bytes_sent/bytes_received 由数据面桥接结束时累加
    /// （`record_traffic`），仅统计完整结束的转发会话；被强杀/取消的
    /// 连接不计数。
    pub fn render_prometheus(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        }
        fn counter(out: &mut String, name: &str, help: &str, value: usize) {
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                name, help, name, name, value
            ));
        }
        fn gauge(out: &mut String, name: &str, help: &str, value: usize) {
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                name, help, name, name, value
            ));
        }

        let mut out = String::with_capacity(2048);
        gauge(
            &mut out,
            "frps_uptime_seconds",
            "Server uptime in seconds",
            self.uptime().as_secs() as usize,
        );
        counter(
            &mut out,
            "frps_connections_total",
            "Total visitor connections accepted",
            self.total_connections.load(Ordering::SeqCst),
        );
        gauge(
            &mut out,
            "frps_connections_current",
            "Current visitor connections",
            self.current_connections.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_proxies_total",
            "Total proxies registered",
            self.total_proxies.load(Ordering::SeqCst),
        );
        gauge(
            &mut out,
            "frps_proxies_current",
            "Current registered proxies",
            self.current_proxies.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_traffic_bytes_sent_total",
            "Bytes sent (not wired in dataplane, always 0)",
            self.bytes_sent.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_traffic_bytes_received_total",
            "Bytes received (not wired in dataplane, always 0)",
            self.bytes_received.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_login_successes_total",
            "Successful client logins",
            self.login_successes.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_login_failures_total",
            "Failed client logins",
            self.login_failures.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_tls_rejects_total",
            "TLS handshake rejections",
            self.tls_rejects.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_work_conn_total",
            "Work connections registered",
            self.work_conn_total.load(Ordering::SeqCst),
        );

        // per-proxy 指标（label: name/type）
        let stats = self
            .proxy_stats
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for stat in stats.values() {
            let labels = format!(
                "{{name=\"{}\",type=\"{}\"}}",
                esc(&stat.name),
                esc(&stat.proxy_type)
            );
            out.push_str(&format!(
                "# HELP frps_proxy_conns_current Current connections per proxy\n# TYPE frps_proxy_conns_current gauge\nfrps_proxy_conns_current{} {}\n",
                labels, stat.current_conns.load(Ordering::SeqCst)
            ));
            out.push_str(&format!(
                "# TYPE frps_proxy_conns_total counter\nfrps_proxy_conns_total{} {}\n",
                labels,
                stat.total_conns.load(Ordering::SeqCst)
            ));
            out.push_str(&format!(
                "# TYPE frps_proxy_traffic_bytes_in_total counter\nfrps_proxy_traffic_bytes_in_total{} {}\n",
                labels,
                stat.bytes_in.load(Ordering::SeqCst)
            ));
            out.push_str(&format!(
                "# TYPE frps_proxy_traffic_bytes_out_total counter\nfrps_proxy_traffic_bytes_out_total{} {}\n",
                labels,
                stat.bytes_out.load(Ordering::SeqCst)
            ));
        }
        out
    }
}

/// 进程级监控指标单例：供 Control::run 等深层调用点零参数获取，
/// 避免给已超长的构造参数链加参。Server::new 时注册。
static GLOBAL_METRICS: std::sync::OnceLock<std::sync::Arc<MonitorMetrics>> =
    std::sync::OnceLock::new();

pub(crate) fn set_global_metrics(metrics: std::sync::Arc<MonitorMetrics>) {
    let _ = GLOBAL_METRICS.set(metrics);
}

/// 获取全局监控指标（Server 尚未初始化时自动创建，用于单元测试等场景）
pub fn global_metrics() -> std::sync::Arc<MonitorMetrics> {
    GLOBAL_METRICS.get().cloned().unwrap_or_else(|| {
        let m = std::sync::Arc::new(MonitorMetrics::new());
        let _ = GLOBAL_METRICS.set(m.clone());
        m
    })
}

#[cfg(test)]
mod traffic_tests {
    use super::*;

    #[test]
    fn test_record_traffic_updates_global_and_proxy_stats() {
        let m = MonitorMetrics::new();
        let stat = m.register_proxy_stat("ssh", "tcp", Some(6000));

        m.record_traffic("ssh", 100, 250);

        assert_eq!(m.bytes_received.load(Ordering::SeqCst), 100);
        assert_eq!(m.bytes_sent.load(Ordering::SeqCst), 250);
        assert_eq!(stat.bytes_in.load(Ordering::SeqCst), 100);
        assert_eq!(stat.bytes_out.load(Ordering::SeqCst), 250);

        // 累加语义
        m.record_traffic("ssh", 1, 2);
        assert_eq!(stat.bytes_in.load(Ordering::SeqCst), 101);
        assert_eq!(stat.bytes_out.load(Ordering::SeqCst), 252);
    }

    #[test]
    fn test_record_traffic_without_proxy_stat_still_counts_global() {
        let m = MonitorMetrics::new();
        m.record_traffic("未知代理", 7, 9);
        assert_eq!(m.bytes_received.load(Ordering::SeqCst), 7);
        assert_eq!(m.bytes_sent.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn test_prometheus_includes_per_proxy_traffic() {
        let m = MonitorMetrics::new();
        m.register_proxy_stat("web", "http", Some(9090));
        m.record_traffic("web", 11, 22);

        let text = m.render_prometheus();
        assert!(text.contains("frps_proxy_traffic_bytes_in_total{name=\"web\",type=\"http\"} 11"));
        assert!(text.contains("frps_proxy_traffic_bytes_out_total{name=\"web\",type=\"http\"} 22"));
        assert!(text.contains("frps_traffic_bytes_received_total"));
        assert!(text.contains("frps_traffic_bytes_sent_total"));
    }
}
