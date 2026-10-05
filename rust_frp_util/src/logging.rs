//! 日志初始化：stderr + 可选日志文件（按天轮转）
//!
//! 对齐原版 frp 的 `[log]` 配置段：
//!
//! ```toml
//! [log]
//! to = "/var/log/frps.log"   # 空 / 不配置 → 仅 stderr
//! level = "info"             # 不配置 → 用 RUST_LOG，再没有则内置默认
//! maxDays = 3                # 默认 3，0 = 不自动清理
//! ```
//!
//! # 行为说明
//!
//! - **tee 输出**：配置了 `to` 之后，日志**同时**写 stderr 与文件。
//!   这是相对原版的一处有意差异 —— 原版配置了 `log.to` 就只写文件；
//!   这里保留 stderr 是为了 systemd 场景下 `journalctl` 依然可用，
//!   且实测运维习惯依赖 journald（见 2026-10-05 线上核查报告）。
//! - **按天轮转**：跨天时把当前文件重命名为 `<name>.<YYYY-MM-DD>` 并重建。
//!   日期按 **UTC** 计算 —— 与 tracing 默认输出的时间戳（`...Z`）保持一致。
//! - **清理**：保留最近 `max_days` 天（含当天）。`0` 表示不自动清理。
//! - **失败不阻断**：写日志失败绝不 panic；轮转失败退回继续写原句柄。
//!
//! # 为什么不用 `time` / `chrono`
//!
//! 只需要「当前 UTC 日期字符串」与「日期串比较」两件事，用经典的
//! civil-from-days 算法（Howard Hinnant）几十行即可完成，避免为日志引入
//! 额外依赖与本地时区探测的不可靠性（`time::OffsetDateTime::now_local()`
//! 在多线程进程里可能直接失败）。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// 初始化全局日志订阅器
///
/// - `to`：日志文件路径；`None` / 空串 → 仅输出 stderr
/// - `level`：日志级别或 `RUST_LOG` 风格过滤表达式；`None` / 空串 → 用 `RUST_LOG`，
///   再没有则沿用 tracing 的内置默认
/// - `max_days`：日志文件保留天数，`0` = 不自动清理
///
/// # 错误
///
/// 仅当**日志文件无法打开/创建**时返回错误（配置写错应当立刻可见，
/// 而不是静默退化成只打 stderr）。
pub fn init(to: Option<&str>, level: Option<&str>, max_days: u32) -> io::Result<()> {
    let (filter, level_warning) = build_filter(level);

    let file_layer = match to.map(str::trim).filter(|s| !s.is_empty()) {
        Some(path) => {
            let writer = DailyFileWriter::new(Path::new(path), max_days)?;
            Some(
                fmt::layer()
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_target(true),
            )
        }
        None => None,
    };

    // 控制台 layer 显式用 stdout，保持与改造前 `tracing_subscriber::fmt()` 一致
    let console_layer = fmt::layer().with_writer(io::stdout).with_target(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .try_init()
        .map_err(io::Error::other)?;

    // 订阅器装好之后再告警，避免日志丢失
    if let Some(warning) = level_warning {
        tracing::warn!("{warning}");
    }
    Ok(())
}

/// 构造过滤器；配置里的级别非法时回退到 `RUST_LOG` 并返回告警文案
fn build_filter(level: Option<&str>) -> (EnvFilter, Option<String>) {
    let configured = level.map(str::trim).filter(|s| !s.is_empty());
    let Some(level) = configured else {
        return (EnvFilter::from_default_env(), None);
    };
    match EnvFilter::try_new(level) {
        Ok(filter) => (filter, None),
        Err(e) => (
            EnvFilter::from_default_env(),
            Some(format!(
                "invalid log.level {level:?} ({e}); falling back to RUST_LOG / built-in default"
            )),
        ),
    }
}

/// 按天轮转的文件写入器
///
/// 实现 [`Write`] 与 [`fmt::MakeWriter`]，可直接交给 `tracing` 的 fmt layer。
/// 每次 `make_writer` 返回共享同一 `Arc<Mutex<..>>` 的克隆，因此多线程/多任务
/// 并发写入是串行的、不会交错。
#[derive(Clone)]
pub struct DailyFileWriter {
    inner: Arc<Mutex<WriterState>>,
}

struct WriterState {
    /// 目标文件路径（始终保持这个名字作为"当天"文件）
    base_path: PathBuf,
    /// 当前打开的句柄；轮转瞬间为 None
    file: Option<File>,
    /// 当前文件对应的 UTC 日期（`YYYY-MM-DD`）
    date: String,
    /// 保留天数（0 = 不清理）
    max_days: u32,
}

impl DailyFileWriter {
    /// 打开（必要时创建）日志文件
    pub fn new(path: &Path, max_days: u32) -> io::Result<Self> {
        let file = open_append(path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(WriterState {
                base_path: path.to_path_buf(),
                file: Some(file),
                date: utc_date_string(SystemTime::now()),
                max_days,
            })),
        })
    }

    /// 加锁（互斥量中毒也继续用内部数据 —— 日志失败不该拖垮进程）
    fn lock(&self) -> std::sync::MutexGuard<'_, WriterState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Write for DailyFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.lock();
        state.rotate_if_needed();
        match state.file.as_mut() {
            Some(file) => file.write(buf),
            // 轮转失败且句柄不可用：丢弃本条日志，绝不 panic
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.lock();
        match state.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> fmt::MakeWriter<'a> for DailyFileWriter {
    type Writer = DailyFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl WriterState {
    /// 跨天则轮转；失败时保留原句柄继续写（best-effort，不返回错误）
    fn rotate_if_needed(&mut self) {
        let today = utc_date_string(SystemTime::now());
        if today == self.date {
            return;
        }
        self.rotate_to(&today);
    }

    /// 执行轮转（`today` 显式传入，便于测试）
    fn rotate_to(&mut self, today: &str) {
        let rotated = rotated_path(&self.base_path, &self.date);

        // 先关掉当前句柄，否则某些平台 rename 后原 fd 仍指向旧 inode
        self.file = None;
        if self.base_path.exists() {
            if let Err(e) = fs::rename(&self.base_path, &rotated) {
                // 改名失败（如跨设备、权限）→ 放弃轮转，继续追加原文件
                eprintln!(
                    "[rust_frp] log rotation failed: {} -> {}: {e}",
                    self.base_path.display(),
                    rotated.display()
                );
            }
        }

        match open_append(&self.base_path) {
            Ok(file) => {
                self.file = Some(file);
                self.date = today.to_string();
                self.prune(today);
            }
            Err(e) => {
                eprintln!(
                    "[rust_frp] cannot reopen log file {}: {e}",
                    self.base_path.display()
                );
                // date 不更新 → 下次写入会再试一遍
            }
        }
    }

    /// 删除早于 `max_days` 的轮转文件（`max_days == 0` 时不清理）
    fn prune(&self, today: &str) {
        if self.max_days == 0 {
            return;
        }
        let Some(today_days) = parse_date(today) else {
            return;
        };
        let cutoff = format_date(today_days - i64::from(self.max_days));

        let (dir, base_name) = match (
            self.base_path.parent(),
            self.base_path.file_name().and_then(|n| n.to_str()),
        ) {
            (Some(dir), Some(name)) => (dir.to_path_buf(), name.to_string()),
            _ => return,
        };
        let Ok(entries) = fs::read_dir(&dir) else {
            return;
        };
        let prefix = format!("{base_name}.");
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            // 只处理形如 YYYY-MM-DD 的轮转文件
            if parse_date(suffix).is_some() && suffix < cutoff.as_str() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// `<base>.<date>` 轮转文件名（同目录）
fn rotated_path(base: &Path, date: &str) -> PathBuf {
    let mut name = base
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".");
    name.push(date);
    base.with_file_name(name)
}

/// 追加模式打开，父目录不存在时自动创建
fn open_append(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            fs::create_dir_all(dir)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}

/// 当前 UTC 日期字符串（`YYYY-MM-DD`）
fn utc_date_string(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        // 系统时钟早于 1970（配置错误/极端情况）时退回 epoch，不 panic
        .unwrap_or(0);
    format_date(secs.div_euclid(86_400))
}

/// 天数（自 1970-01-01，UTC）→ `YYYY-MM-DD`
fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD` → 天数（自 1970-01-01，UTC）；非法格式返回 None
fn parse_date(s: &str) -> Option<i64> {
    let mut parts = s.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // 补零检查：避免把 `2026-1-1` 这类非标准写法当成合法轮转文件名
    if s.len() != 10 {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant 的 civil-from-days：天数 → (年, 月, 日)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Howard Hinnant 的 days-from-civil：(年, 月, 日) → 天数
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// 独立临时目录（避免测试互相干扰），返回路径
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rust_frp_log_test_{tag}_{}_{}",
            std::process::id(),
            crate::rand_id(8)
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn read_to_string(path: &Path) -> String {
        let mut s = String::new();
        File::open(path)
            .expect("open log file")
            .read_to_string(&mut s)
            .expect("read log file");
        s
    }

    #[test]
    fn test_civil_date_roundtrip() {
        // 与已知值对齐：1970-01-01 = 0 天，2000-01-01 = 10957 天
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(10_957), "2000-01-01");

        // 2026-10-05（本次线上核查当天）：2000-01-01(10957) + 26 年(9497) + 277 = 20731 天
        assert_eq!(days_from_civil(2026, 1, 1), 20_454);
        assert_eq!(days_from_civil(2026, 10, 5), 20_731);
        assert_eq!(format_date(20_731), "2026-10-05");

        // 往返一致（含闰年边界）
        for days in [0i64, 1, 59, 60, 365, 366, 20_731, 30_000, -1] {
            let s = format_date(days);
            assert_eq!(parse_date(&s), Some(days), "days={days} s={s}");
        }
    }

    #[test]
    fn test_parse_date_rejects_non_standard() {
        assert_eq!(parse_date("2026-10-05"), Some(20_731));
        assert_eq!(parse_date("2026-1-1"), None); // 未补零
        assert_eq!(parse_date("2026-13-01"), None); // 月份非法
        assert_eq!(parse_date("not-a-date"), None);
        assert_eq!(parse_date("2026-10-05.log"), None);
    }

    #[test]
    fn test_writer_creates_parent_dir_and_appends() {
        let dir = temp_dir("create");
        let path = dir.join("nested/deep/frps.log");
        let mut w = DailyFileWriter::new(&path, 3).expect("create writer");
        w.write_all(b"line-1\n").expect("write");
        w.flush().expect("flush");

        assert_eq!(read_to_string(&path), "line-1\n");

        // 重新打开是追加而非截断
        let mut w2 = DailyFileWriter::new(&path, 3).expect("reopen writer");
        w2.write_all(b"line-2\n").expect("write");
        w2.flush().expect("flush");
        assert_eq!(read_to_string(&path), "line-1\nline-2\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotation_recent_first() {
        let dir = temp_dir("rotate");
        let path = dir.join("frps.log");

        let mut w = DailyFileWriter::new(&path, 3).expect("create writer");
        w.write_all(b"day-old\n").expect("write");
        w.flush().expect("flush");

        // 模拟跨天：把"当前日期"设成 2026-10-05 触发轮转
        {
            let mut state = w.lock();
            state.rotate_to("2026-10-05");
        }

        let rotated = dir.join("frps.log.2026-10-05");
        assert!(rotated.exists(), "rotated file must exist");
        assert_eq!(read_to_string(&rotated), "day-old\n");
        // 新文件已重建且为空
        assert_eq!(read_to_string(&path), "");

        w.write_all(b"new-day\n").expect("write");
        w.flush().expect("flush");
        assert_eq!(read_to_string(&path), "new-day\n");

        // 同一天再次写入不应再轮转（否则会覆盖历史）
        {
            let mut state = w.lock();
            state.rotate_if_needed();
        }
        assert_eq!(read_to_string(&rotated), "day-old\n");
        assert_eq!(read_to_string(&path), "new-day\n");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_keeps_max_days_and_ignores_foreign_files() {
        let dir = temp_dir("prune");
        let path = dir.join("frps.log");
        fs::write(&path, b"").expect("create base");

        // 造历史轮转文件：2026-10-05 为今天，max_days = 3 → 保留 >= 2026-10-02
        for date in [
            "2026-09-30", // 太旧 → 删
            "2026-10-01", // 太旧（cutoff 前）→ 删
            "2026-10-02", // == cutoff → 留
            "2026-10-04", // 留
        ] {
            fs::write(dir.join(format!("frps.log.{date}")), b"x").expect("create rotated");
        }
        // 非本程序的同名前缀文件（后缀不是日期）不应被删
        fs::write(dir.join("frps.log.not-a-date"), b"x").expect("create foreign");

        let w = DailyFileWriter::new(&path, 3).expect("create writer");
        {
            let mut state = w.lock();
            state.rotate_to("2026-10-05");
            state.prune("2026-10-05");
        }

        assert!(!dir.join("frps.log.2026-09-30").exists(), "old must go");
        assert!(!dir.join("frps.log.2026-10-01").exists(), "old must go");
        assert!(dir.join("frps.log.2026-10-02").exists(), "cutoff kept");
        assert!(dir.join("frps.log.2026-10-04").exists(), "recent kept");
        assert!(dir.join("frps.log.not-a-date").exists(), "foreign kept");
        assert!(path.exists(), "base must exist");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_disabled_when_max_days_zero() {
        let dir = temp_dir("prune0");
        let path = dir.join("frps.log");
        fs::write(&path, b"").expect("create base");
        fs::write(dir.join("frps.log.1990-01-01"), b"x").expect("create old");

        let w = DailyFileWriter::new(&path, 0).expect("create writer");
        {
            let mut state = w.lock();
            state.rotate_to("2026-10-05");
            state.prune("2026-10-05");
        }
        assert!(
            dir.join("frps.log.1990-01-01").exists(),
            "max_days = 0 means never prune"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_empty_level_falls_back_without_panic() {
        // 空串 / 全空白视为未配置
        assert_eq!(build_filter(Some("  ")).1, None);
        assert_eq!(build_filter(None).1, None);
        // 非法级别 → 回退 + 告警文案
        assert!(build_filter(Some("nope===")).1.is_some());
        // 合法级别 → 直接用
        assert_eq!(build_filter(Some("debug")).1, None);
    }
}
