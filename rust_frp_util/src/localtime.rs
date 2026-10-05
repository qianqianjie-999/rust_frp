//! 本地时区时间格式化
//!
//! 日志行时间戳、日志轮转日期、管理 API 展示时间都从这里取格式化结果，
//! 保证"同一个时刻在日志和 API 里写法一致"，不会出现一处本地时间、一处 UTC。
//!
//! # 语义
//!
//! 所有 `*_local_*` 函数输出的都是**进程本地时区**时间（`2026-10-05 12:24:34`
//! 或 RFC 3339 `2026-10-05T12:24:34.123456+08:00`），时区取自 `TZ` 环境变量与
//! `/etc/localtime`；无法确定时回退 UTC（并显式写成 `+00:00`，让偏移量自证）。
//!
//! 需要强制某个时区就给进程设 `TZ`（systemd 单元里 `Environment=TZ=Asia/Shanghai`）。
//!
//! # 时区是怎么拿到的
//!
//! 用 libc 的 [`libc::localtime_r`]（可重入、线程安全）读取偏移，其余全部是纯 Rust
//! 的民用历算法（Howard Hinnant civil-from-days）。
//!
//! 之所以不用 `time` / `chrono`：`time` 的 `UtcOffset::current_local_offset()` 在多线程
//! 进程里**会直接返回 Err**（我们跑在 tokio 多线程 runtime 上），而 `tracing_subscriber`
//! 的 `LocalTime` 正是基于它 —— 那会导致时间戳静默退化成 UTC，即 2026-10-05 修的那个问题。
//! `libc` 只是 FFI 声明：无 C 代码、不要求 C 工具链，且早已是 tokio 的传递依赖。

use std::time::{SystemTime, UNIX_EPOCH};

/// `SystemTime` → Unix 秒（早于 1970 时退回 0）
fn unix_secs(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 当前本地时区相对 UTC 的偏移（秒）；无法确定时回退 `0`（即 UTC）
///
/// 供调用方判断"是否真的拿到了本地时区"（`0` 既可能是 UTC 时区，
/// 也可能是取不到时区的兜底值）。
pub fn local_offset_secs() -> i32 {
    offset_secs_at(unix_secs(SystemTime::now()))
}

/// Unix 秒 → 本地 `YYYY-MM-DD HH:MM:SS`（管理 API / 运维展示用）
///
/// 不做 `<= 0` 之类的业务裁剪（1970 年前的时刻照实输出），
/// "未记录 → 空串"这类展示语义由调用方决定。
pub fn format_local_datetime(secs: i64) -> String {
    format_local_datetime_with_offset(secs, offset_secs_at(secs))
}

/// [`format_local_datetime`] 的纯函数版本：偏移显式传入
///
/// 时区作为参数而不是环境依赖，测试才能确定性地断言跨时区/跨天结果。
pub(crate) fn format_local_datetime_with_offset(secs: i64, offset_secs: i32) -> String {
    let (days, sec_of_day) = local_parts(secs, offset_secs);
    format!("{} {}", format_date(days), format_clock(sec_of_day))
}

/// 本地 RFC 3339 时间戳（`2026-10-05T12:24:34.123456+08:00`）
///
/// 带显式偏移量后缀：既不产生歧义，也不需要运维心算时差。
/// `micros` 为微秒部分（0..1_000_000）。
pub(crate) fn format_local_timestamp(utc_secs: i64, micros: u32, offset_secs: i32) -> String {
    let (days, sec_of_day) = local_parts(utc_secs, offset_secs);
    format!(
        "{}T{}.{:06}{}",
        format_date(days),
        format_clock(sec_of_day),
        micros,
        OffsetDisplay(offset_secs)
    )
}

/// 当前**本地**日期字符串（`YYYY-MM-DD`），日志轮转按它切分
pub(crate) fn local_date_string(now: SystemTime) -> String {
    let secs = unix_secs(now);
    format_date(local_parts(secs, offset_secs_at(secs)).0)
}

// ─────────────────────────── 时区偏移 ───────────────────────────

/// 时区偏移的 RFC 3339 写法（`+08:00` / `-05:30` / `+00:00`）
struct OffsetDisplay(i32);

impl std::fmt::Display for OffsetDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sign = if self.0 < 0 { '-' } else { '+' };
        let abs = self.0.unsigned_abs();
        write!(f, "{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
    }
}

/// 指定 Unix 秒时刻的本地时区偏移（秒）；无法确定时回退 `0`（即 UTC）
///
/// 历史时间戳（如代理上次下线时刻）按**当时**的偏移换算，而不是复用"当前偏移"，
/// 夏令时切换区间才不会错一小时。走 libc `localtime_r`：会读取 `TZ` 环境变量与
/// `/etc/localtime`，因此能正确处理夏令时与 `+05:30`/`+05:45` 这类非整点时区。
#[cfg(unix)]
pub(crate) fn offset_secs_at(secs: i64) -> i32 {
    // 32 位平台的 time_t 是 i32，超出范围必须退回 UTC（不能截断成错误日期），
    // 所以用可失败转换；64 位平台上该转换恒成功、`else` 分支不可达，故两个 lint
    // 一并放行。`deprecated` 的来由：musl 目标的 `libc::time_t` 已被标 deprecated
    // （musl 1.2 起 time_t 由 32 位改 64 位，libc 未来版本会跟进改名），此处只是照
    // `localtime_r` 的现有签名传参，取值在 32/64 位两种宽度下都安全。
    #[allow(irrefutable_let_patterns, deprecated)]
    let Ok(secs) = libc::time_t::try_from(secs) else {
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
pub(crate) fn offset_secs_at(_secs: i64) -> i32 {
    0
}

// ─────────────────────────── 民用历换算 ───────────────────────────

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

/// 天数（自 1970-01-01 的天数，与时区无关）→ `YYYY-MM-DD`
pub(crate) fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD` → 天数（自 1970-01-01 的天数）；非法格式返回 None
///
/// 供日志轮转清理识别 `<name>.<YYYY-MM-DD>` 文件。
pub(crate) fn parse_date(s: &str) -> Option<i64> {
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

    /// 2026-10-05T00:00:00Z 的 Unix 秒（20731 天 × 86400）
    const UTC_2026_10_05: i64 = 20_731 * 86_400;

    #[test]
    fn test_civil_date_roundtrip() {
        // 与已知值对齐：1970-01-01 = 0 天，2000-01-01 = 10957 天
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(10_957), "2000-01-01");

        // 2026-10-05（2026 年线上核查当天）
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

    /// 管理 API 用的 `YYYY-MM-DD HH:MM:SS`：偏移注入，断言与宿主时区无关
    #[test]
    fn test_format_local_datetime_with_offset() {
        // 东八区：UTC 22:13:20 → 本地次日 06:13:20（跨天，并且与 UTC 串不同）
        assert_eq!(
            format_local_datetime_with_offset(1_700_000_000, 8 * 3600),
            "2023-11-15 06:13:20"
        );
        assert_eq!(
            format_local_datetime_with_offset(1_700_000_000, 0),
            "2023-11-14 22:13:20"
        );
        // 负偏移回退一天
        assert_eq!(
            format_local_datetime_with_offset(1_700_000_000, -5 * 3600),
            "2023-11-14 17:13:20"
        );
        // epoch 与 1970 年前（不裁剪，业务语义由调用方决定）
        assert_eq!(
            format_local_datetime_with_offset(0, 0),
            "1970-01-01 00:00:00"
        );
        assert_eq!(
            format_local_datetime_with_offset(-1, 0),
            "1969-12-31 23:59:59"
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
        let offset = local_offset_secs();
        assert!(
            (-14 * 3600..=14 * 3600).contains(&offset),
            "offset out of range: {offset}"
        );
        // 按历史时刻取值同样合法（夏令时切换区间也不越界）
        let historical = offset_secs_at(1_700_000_000);
        assert!(
            (-14 * 3600..=14 * 3600).contains(&historical),
            "offset out of range: {historical}"
        );
        // 日期串必须是可解析的标准形式（供轮转/清理复用）
        let today = local_date_string(SystemTime::now());
        assert!(parse_date(&today).is_some(), "bad local date: {today}");
    }

    /// 公开入口的诚实性：拿不到时区时（偏移 0）输出必须等于 UTC 表示，
    /// 且格式化结果只取决于注入偏移 —— 防止哪天有人把它改回 `SystemTime` 默认 UTC。
    #[test]
    fn test_format_local_datetime_matches_injected_offset() {
        let now = unix_secs(SystemTime::now());
        let offset = local_offset_secs();
        assert_eq!(
            format_local_datetime(now),
            format_local_datetime_with_offset(now, offset)
        );
        // 秒级时间戳必须是 19 字符定长（前端按定长渲染）
        assert_eq!(format_local_datetime(now).len(), 19);
    }
}
