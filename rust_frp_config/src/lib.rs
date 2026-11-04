//! # rust_frp_config - FRP 配置管理模块
//!
//! 本模块负责配置文件的解析、验证和处理。
//!
//! ## 支持的配置文件格式
//!
//! 按优先级尝试解析以下格式：
//! 1. **TOML** (推荐)
//! 2. **YAML**
//! 3. **JSON**
//!
//! ## 环境变量替换
//!
//! 配置值中可使用 `${VAR_NAME}` 语法引用环境变量：
//! ```toml
//! server_addr = "${FRP_SERVER_ADDR}"
//! token = "${FRP_TOKEN}"
//! ```
//!
//! ## 配置包含 (includes)
//!
//! 支持通过 glob 模式包含其他配置文件：
//! ```toml
//! includes = ["/etc/frp.d/*.toml"]
//! ```
//!
//! ## 默认值
//!
//! 所有配置项都有合理的默认值，可参考各结构的 `Default` 实现。

use glob::glob;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

mod compat;

use compat::ConfigKind;

mod types;
pub use types::*;

mod loader;
pub use loader::*;

#[cfg(test)]
pub(crate) fn compat_test_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[cfg(test)]
mod tests;
