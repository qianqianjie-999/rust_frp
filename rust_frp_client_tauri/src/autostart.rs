//! 开机自启（HKCU\Software\Microsoft\Windows\CurrentVersion\Run）
//!
//! 用注册表 API 直读写，**不 spawn reg.exe**：托盘应用弹子进程会闪控制台
//! 黑窗，且部分安全软件会拦截。无需管理员权限（HKCU 当前用户项）。

use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_READ, REG_SZ,
};

const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "rust_frpc-gui";

/// 当前可执行文件路径（注册表写入目标）
pub fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rust_frpc-gui.exe"))
}

/// 自启是否已启用
pub fn is_enabled() -> bool {
    let Some(key) = open_run_key(KEY_READ) else {
        return false;
    };
    let name = to_wide(RUN_VALUE);
    // 只探测存在性与类型，不取值
    let rc = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    unsafe { RegCloseKey(key) };
    rc == ERROR_SUCCESS
}

/// 启用/关闭自启
pub fn set_enabled(enable: bool) -> Result<(), String> {
    let Some(key) = open_run_key(KEY_ALL_ACCESS) else {
        return Err(format!("无法打开注册表项 HKCU\\{RUN_SUBKEY}"));
    };
    let name = to_wide(RUN_VALUE);

    let rc = if enable {
        // 值带引号，防止路径含空格时被拆分
        let value = to_wide(&format!("\"{}\"", exe_path().display()));
        let bytes = as_bytes(&value);
        unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        }
    } else {
        unsafe { RegDeleteValueW(key, name.as_ptr()) }
    };
    unsafe { RegCloseKey(key) };

    // 删除不存在的值也视为成功（幂等）
    let ok = rc == ERROR_SUCCESS || (!enable && rc == ERROR_FILE_NOT_FOUND);
    if ok {
        log::info!("开机自启{}", if enable { "已开启" } else { "已关闭" });
        Ok(())
    } else {
        Err(format!("注册表操作失败，错误码 {rc}"))
    }
}

/// 打开 Run 键（失败返回 None：不存在或无权限）
fn open_run_key(access: u32) -> Option<HKEY> {
    let subkey = to_wide(RUN_SUBKEY);
    let mut key: HKEY = unsafe { std::mem::zeroed() };
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut key) };
    if rc == ERROR_SUCCESS {
        Some(key)
    } else {
        None
    }
}

/// &str → 以 NUL 结尾的 UTF-16 宽串
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// &[u16] → &[u8]（REG_SZ 写入用，长度含 NUL 终止符）
fn as_bytes(v: &[u16]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}
