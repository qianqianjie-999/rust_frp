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
//! - **本地时间**：日志行时间戳与轮转文件名的日期都用**进程本地时区**
//!   （`2026-10-05T12:24:34.123456+08:00`），与原版 frp 的 Go `log` 行为一致。
//!   时区取自 `TZ` 环境变量 / `/etc/localtime`，无法确定时回退 UTC。
//! - **按天轮转**：跨天时把当前文件重命名为 `<name>.<YYYY-MM-DD>` 并重建。
//!   日期同样按**本地时区**计算，与日志行时间戳严格一致。
//! - **清理**：保留最近 `max_days` 天（含当天）。`0` 表示不自动清理。
//! - **失败不阻断**：写日志失败绝不 panic；轮转失败退回继续写原句柄。
//!
//! # 时区是怎么拿到的
//!
//! 用 libc 的 [`localtime_r`]（可重入、线程安全）读取当前偏移，其余全部是纯 Rust
//! 的民用历算法（Howard Hinnant civil-from-days）。
//!
//! 之所以不用 `time` / `chrono`：`time` 的 `UtcOffset::current_local_offset()` 在多线程
//! 进程里**会直接返回 Err**（我们跑在 tokio 多线程 runtime 上），而 `tracing_subscriber`
//! 的 `LocalTime` 正是基于它 —— 那会导致时间戳静默退化成 UTC，即本次要修的问题。
//! `libc` 只是 FFI 声明：无 C 代码、不要求 C 工具链，且早已是 tokio 的传递依赖。
//!
//! 若需要强制某个时区，给进程设 `TZ`（如 systemd 单元里 `Environment=TZ=Asia/Shanghai`）即可。

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
                    .with_timer(LocalTimer)
                    .with_target(true),
            )
        }
        None => None,
    };

    // 控制台 layer 显式用 stdout，保持与改造前 `tracing_subscriber::fmt()` 一致
    let console_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_timer(LocalTimer)
        .with_target(true);

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
                date: local_date_string(SystemTime::now()),
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
        let today = local_date_string(SystemTime::now());
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

// ─────────────────────────── 本地时间 ───────────────────────────

/// tracing 计时器：输出**本地时间** RFC 3339（`2026-10-05T12:24:34.123456+08:00`）
///
/// 相对于 tracing 默认的 [`fmt::time::SystemTime`]（UTC + `Z` 后缀），这里带显式
/// 偏移量，既不产生歧义，也不需要运维心算时差。
#[derive(Clone, Copy, Default)]
pub struct LocalTimer;

impl fmt::time::FormatTime for LocalTimer {
    fn format_time(&self, w: &mut fmt::format::Writer<'_>) -> std::fmt::Result {
        // 系统时钟早于 1970（配置错误/极端情况）时退回 epoch，不 panic
        let now = SystemTime::now();
        let elapsed = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        // 复用 `format_local_timestamp`：格式化逻辑只有一份，不会与测试漂移
        // （`Writer::write_str` 是固有方法，无需引入 fmt::Write）
        w.write_str(&format_local_timestamp(
            elapsed.as_secs() as i64,
            elapsed.subsec_micros(),
            local_offset_secs_at(now),
        ))
    }
}

/// 时区偏移的 RFC 3339 写法（`+08:00` / `-05:30` / `+00:00`）
struct OffsetDisplay(i32);

impl std::fmt::Display for OffsetDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sign = if self.0 < 0 { '-' } else { '+' };
        let abs = self.0.unsigned_abs();
        write!(f, "{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
    }
}

/// `SystemTime` → Unix 秒（早于 1970 时退回 0）
fn unix_secs(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 进程本地时区相对 UTC 的偏移（秒）；无法确定时回退 `0`（即 UTC）
///
/// 走 libc 的 `localtime_r`：可重入（线程安全），会读取 `TZ` 环境变量与
/// `/etc/localtime`，因此能正确处理夏令时与 `+05:30`/`+05:45` 这类非整点时区。
#[cfg(unix)]
fn local_offset_secs_at(now: SystemTime) -> i32 {
    // 走 u64 → time_t 的**可失败**转换：32 位平台的 time_t 是 i32，这里要能拒绝
    let secs_u64 = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // musl 目标的 `libc::time_t` 被标了 deprecated（musl 1.2 起 time_t 由 32 位改 64 位，
    // libc 将在未来版本跟进改名）。这里只是照 `localtime_r` 的现有签名传参，取值在
    // 32/64 位两种宽度下都安全，故就地放行；待 libc 提供稳定别名后移除本 allow。
    #[allow(deprecated)]
    let Ok(secs) = libc::time_t::try_from(secs_u64) else {
        return 0;
    };
    // SAFETY: `secs` 是栈上值、`tm` 是栈上已初始化的有效目标，`localtime_r`
    // 是 POSIX 规定的可重入接口，不会保留参数引用。
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let filled = unsafe { !libc::localtime_r(&secs, &mut tm).is_null() };
    if filled {
        tm.tm_gmtoff as i32
    } else {
        0
    }
}

/// 非 Unix 平台没有 `tm_gmtoff`，退回 UTC（不 panic）
#[cfg(not(unix))]
fn local_offset_secs_at(_now: SystemTime) -> i32 {
    0
}

/// 当前**本地**日期字符串（`YYYY-MM-DD`）
fn local_date_string(now: SystemTime) -> String {
    let (days, _) = local_parts(unix_secs(now), local_offset_secs_at(now));
    format_date(days)
}

/// UTC 秒 + 偏移 → （自 1970-01-01 的天数, 当日秒）
///
/// 纯函数，便于测试；`div_euclid`/`rem_euclid` 保证负偏移方向正确。
fn local_parts(utc_secs: i64, offset_secs: i32) -> (i64, u32) {
    let shifted = utc_secs + i64::from(offset_secs);
    (
        shifted.div_euclid(86_400),
        shifted.rem_euclid(86_400) as u32,
    )
}

/// 当日秒 → `HH:MM:SS`
fn format_clock(sec_of_day: u32) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        sec_of_day / 3600,
        (sec_of_day % 3600) / 60,
        sec_of_day % 60
    )
}

/// 纯函数版时间戳（供测试复用；`micros` 为微秒部分）
fn format_local_timestamp(utc_secs: i64, micros: u32, offset_secs: i32) -> String {
    let (days, sec_of_day) = local_parts(utc_secs, offset_secs);
    format!(
        "{}T{}.{:06}{}",
        format_date(days),
        format_clock(sec_of_day),
        micros,
        OffsetDisplay(offset_secs)
    )
}

/// 天数（自 1970-01-01 的天数，民用历，与时区无关）→ `YYYY-MM-DD`
fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD` → 天数（自 1970-01-01 的天数）；非法格式返回 None
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

    /// 2026-10-05T00:00:00Z 的 Unix 秒（20731 天 × 86400）
    const UTC_2026_10_05: i64 = 20_731 * 86_400;

    #[test]
    fn test_local_parts_applies_offset_both_directions() {
        // 东八区：UTC 00:00 → 本地同日 08:00
        assert_eq!(local_parts(UTC_2026_10_05, 8 * 3600), (20_731, 28_800));
        // 跨天向前：UTC 16:00(+8h) → 本地次日 00:00
        let (days, sod) = local_parts(UTC_2026_10_05 + 16 * 3600, 8 * 3600);
        assert_eq!((days, sod), (20_732, 0));
        // 跨天向后：UTC 00:00(-5h) → 本地前一日 19:00
        let (days, sod) = local_parts(UTC_2026_10_05, -5 * 3600);
        assert_eq!((days, sod), (20_730, 68_400));
        // 负偏移跨 epoch：UTC 0 - 8h → 1969-12-31 16:00
        let (days, sod) = local_parts(0, -8 * 3600);
        assert_eq!((days, sod), (-1, 57_600));
        assert_eq!(format_date(-1), "1969-12-31");
    }

    #[test]
    fn test_format_local_timestamp_with_offset_suffix() {
        // 东八区
        assert_eq!(
            format_local_timestamp(UTC_2026_10_05, 123_456, 8 * 3600),
            "2026-10-05T08:00:00.123456+08:00"
        );
        // UTC 显式写成 +00:00（而不是 Z）—— 让偏移量自证，避免"忘了配时区"被误读
        assert_eq!(
            format_local_timestamp(UTC_2026_10_05, 0, 0),
            "2026-10-05T00:00:00.000000+00:00"
        );
        // 半整点时区（印度 +05:30）与负偏移
        assert_eq!(
            format_local_timestamp(UTC_2026_10_05, 1, 19_800),
            "2026-10-05T05:30:00.000001+05:30"
        );
        assert_eq!(
            format_local_timestamp(UTC_2026_10_05, 0, -5 * 3600),
            "2026-10-04T19:00:00.000000-05:00"
        );
        // 45 分钟时区（尼泊尔 +05:45）
        assert_eq!(
            format_local_timestamp(UTC_2026_10_05, 0, 20_700),
            "2026-10-05T05:45:00.000000+05:45"
        );
    }

    #[test]
    fn test_format_clock_padding() {
        assert_eq!(format_clock(0), "00:00:00");
        assert_eq!(format_clock(28_800), "08:00:00");
        assert_eq!(format_clock(86_399), "23:59:59");
    }

    /// 真实环境取偏移：本机 `/etc/localtime` 指向何处都不得 panic，
    /// 且结果必须落在 `-14:00..=+14:00` 的合法时区范围内。
    #[test]
    fn test_local_offset_is_sane() {
        let offset = local_offset_secs_at(SystemTime::now());
        assert!(
            (-14 * 3600..=14 * 3600).contains(&offset),
            "offset out of range: {offset}"
        );
        // 日期串必须是可解析的标准形式（供轮转/清理复用）
        let today = local_date_string(SystemTime::now());
        assert!(parse_date(&today).is_some(), "bad local date: {today}");
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
