#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_frp_net::wire_v2::read_frame;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("构建 runtime 失败");

    rt.block_on(async {
        let mut cursor = Cursor::new(data);
        // 帧头（类型/标志/长度）来自不可信网络输入，任何字节组合都必须
        // 以 Err 结束，不能越界、不能 panic。
        let _ = read_frame(&mut cursor).await;
    });
});
