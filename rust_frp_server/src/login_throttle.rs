//! 控制口登录失败节流（P1 / B4）
//!
//! 背景：控制口（默认 9300）此前**没有任何 throttle / lockout** —— 持有（或猜测）
//! token 的一方可无限次重试登录。本模块提供"失败 N 次锁 M 秒"的最小实现。
//!
//! 设计取舍：
//! - **以 `client_id` 为主维度**。线上两台 frpc 均为动态 IP + 运营商 NAT，
//!   纯按来源 IP 限流会把同出口的其他客户端一起误伤；`client_id` 是客户端自报的，
//!   但也更贴近"具体是谁在试"。无法拿到 `client_id` 时退化为按 IP 计。
//! - **登录成功立即清零**，避免正常客户端偶发抖动后被"记仇"。
//! - 计数只增不永久累积：锁定到期即清除条目，并对表做容量兜底修剪，防止内存被刷爆。
//! - 锁定期间**直接拒绝**且不消耗 CPU（不做密码学运算、不查 token），顺带缓解暴力破解。
//!
//! 用 `std::sync::Mutex` 而非 tokio 锁：临界区内只做 HashMap 读写，不跨 `await`，
//! 无可重入风险。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 节流维度的键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThrottleKey {
    /// 客户端自报的 `client_id`（首选维度）
    Client(String),
    /// 退化为来源 IP（客户端未给出 `client_id` 时）
    Ip(IpAddr),
}

impl ThrottleKey {
    /// 由登录消息中的 `client_id` 与来源 IP 构造键。
    ///
    /// `client_id` 为空时退回按 IP 计 —— 此时无法区分同 NAT 后的不同客户端，
    /// 但"完全不计"更糟。
    pub fn new(client_id: &str, ip: Option<IpAddr>) -> Option<Self> {
        let client_id = client_id.trim();
        if !client_id.is_empty() {
            return Some(Self::Client(client_id.to_string()));
        }
        ip.map(Self::Ip)
    }
}

impl std::fmt::Display for ThrottleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(id) => write!(f, "client_id='{id}'"),
            Self::Ip(ip) => write!(f, "ip={ip}"),
        }
    }
}

#[derive(Debug)]
struct Entry {
    failures: u32,
    last_failure: Instant,
    locked_until: Option<Instant>,
}

/// 登录失败节流器（线程安全，可跨连接共享）
#[derive(Debug)]
pub struct LoginThrottle {
    max_failures: u32,
    lockout: Duration,
    /// 失败计数保留窗口：超过该时长未再失败的条目视为"陈年旧账"，可被清理
    window: Duration,
    state: Mutex<HashMap<ThrottleKey, Entry>>,
}

/// 节流表的容量上限（超过则触发一次过期修剪，防止被刷爆内存）
const MAX_ENTRIES: usize = 4096;

impl LoginThrottle {
    /// 构造节流器；`max_failures = 0` 表示**关闭节流**，返回 `None`。
    pub fn new(max_failures: u32, lockout_secs: u64) -> Option<Self> {
        if max_failures == 0 || lockout_secs == 0 {
            return None;
        }
        let lockout = Duration::from_secs(lockout_secs);
        Some(Self {
            max_failures,
            // 失败计数保留窗口取锁定窗口与 1 小时的较大者：锁定短也不至于刚记完就忘
            window: lockout.max(Duration::from_secs(3600)),
            lockout,
            state: Mutex::new(HashMap::new()),
        })
    }

    /// 是否处于锁定中。返回 `Err(剩余时长)` 表示应拒绝本次登录尝试。
    pub fn check(&self, key: &ThrottleKey) -> Result<(), Duration> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = state.get_mut(key) else {
            return Ok(());
        };
        match entry.locked_until {
            Some(until) if until > now => Err(until - now),
            Some(_) => {
                // 锁定已过期：清账，允许再试
                state.remove(key);
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// 记录一次登录失败，返回该键当前的连续失败次数。
    pub fn record_failure(&self, key: &ThrottleKey) -> u32 {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.len() >= MAX_ENTRIES {
            let window = self.window;
            state.retain(|_, e| {
                now.duration_since(e.last_failure) < window
                    && e.locked_until.map(|u| u > now).unwrap_or(false)
            });
        }
        let entry = state.entry(key.clone()).or_insert(Entry {
            failures: 0,
            last_failure: now,
            locked_until: None,
        });
        // 距上次失败已超出保留窗口 ⇒ 视为新的一轮
        if now.duration_since(entry.last_failure) > self.window {
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = now;
        if entry.failures >= self.max_failures {
            entry.locked_until = Some(now + self.lockout);
        }
        entry.failures
    }

    /// 登录成功：清零该键的失败计数与锁定。
    pub fn record_success(&self, key: &ThrottleKey) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(key);
    }

    /// 当前锁定条目数（仅供测试与观测）
    pub fn locked_count(&self) -> usize {
        let now = Instant::now();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .values()
            .filter(|e| e.locked_until.map(|u| u > now).unwrap_or(false))
            .count()
    }

    pub fn max_failures(&self) -> u32 {
        self.max_failures
    }

    pub fn lockout(&self) -> Duration {
        self.lockout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> ThrottleKey {
        ThrottleKey::new(id, None).expect("non-empty id")
    }

    #[test]
    fn disabled_when_zero() {
        assert!(LoginThrottle::new(0, 600).is_none());
        assert!(LoginThrottle::new(5, 0).is_none());
    }

    #[test]
    fn locks_after_threshold_and_reports_remaining() {
        let t = LoginThrottle::new(3, 600).unwrap();
        let k = key("cli32-abc");
        assert!(t.check(&k).is_ok());
        assert_eq!(t.record_failure(&k), 1);
        assert!(t.check(&k).is_ok(), "未达阈值不应锁定");
        assert_eq!(t.record_failure(&k), 2);
        assert!(t.check(&k).is_ok());
        assert_eq!(t.record_failure(&k), 3);
        let remaining = t.check(&k).expect_err("达到阈值应锁定");
        assert!(remaining > Duration::from_secs(500), "剩余 {remaining:?}");
        assert_eq!(t.locked_count(), 1);
    }

    #[test]
    fn success_clears_counter() {
        let t = LoginThrottle::new(2, 600).unwrap();
        let k = key("cli75-xyz");
        t.record_failure(&k);
        t.record_success(&k);
        // 清零后再失败一次不应锁定
        assert_eq!(t.record_failure(&k), 1);
        assert!(t.check(&k).is_ok());
    }

    #[test]
    fn keys_are_isolated_per_client() {
        let t = LoginThrottle::new(2, 600).unwrap();
        let a = key("cli32");
        let b = key("cli75");
        t.record_failure(&a);
        t.record_failure(&a);
        assert!(t.check(&a).is_err(), "a 应被锁定");
        assert!(t.check(&b).is_ok(), "b 不应受 a 牵连");
    }

    #[test]
    fn falls_back_to_ip_when_client_id_missing() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(ThrottleKey::new("   ", Some(ip)), Some(ThrottleKey::Ip(ip)));
        assert_eq!(ThrottleKey::new("", None), None, "两者皆无则无法计");
        assert_eq!(
            ThrottleKey::new("cli32", Some(ip)),
            Some(ThrottleKey::Client("cli32".to_string())),
            "有 client_id 时优先按 client_id"
        );
    }

    #[test]
    fn expired_lockout_is_released() {
        // 用 1 秒锁定验证"到期自动解锁"，避免测试等待过久
        let t = LoginThrottle::new(1, 1).unwrap();
        let k = key("cli32");
        t.record_failure(&k);
        assert!(t.check(&k).is_err());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(t.check(&k).is_ok(), "锁定到期后应放行");
        assert_eq!(t.locked_count(), 0);
    }
}
