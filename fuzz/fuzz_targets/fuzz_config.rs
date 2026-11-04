#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_frp_config::ConfigLoader;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // TOML / YAML / JSON 三种格式的自动探测与兼容转换都在这一条路径上，
    // 断言它面对任意输入只能返回 Err，不能 panic。
    let _ = ConfigLoader::validate_server_config_content(text);
    let _ = ConfigLoader::validate_client_config_content(text);
});
