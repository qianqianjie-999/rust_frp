//! wire protocol v2 帧读取基准（零额外依赖）。
//!
//! 运行：`cargo bench -p rust_frp_net --bench wire_frame`
//!
//! 覆盖 8 字节帧头 + 不同载荷长度的解析路径，防止帧解析出现数量级回退。

use rust_frp_net::wire_v2::{read_frame, FRAME_TYPE_MESSAGE};
use std::io::Cursor;
use std::time::{Duration, Instant};

fn bench(label: &str, payload_len: usize, iters: u32, rt: &tokio::runtime::Runtime) {
    let payload = vec![b'x'; payload_len];
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&FRAME_TYPE_MESSAGE.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);

    // 预热
    for _ in 0..(iters / 10).max(1) {
        let mut cursor = Cursor::new(bytes.as_slice());
        let _ = rt.block_on(read_frame(&mut cursor));
    }

    let mut total = Duration::ZERO;
    let mut ok = 0u32;
    for _ in 0..iters {
        let mut cursor = Cursor::new(bytes.as_slice());
        let start = Instant::now();
        if rt.block_on(read_frame(&mut cursor)).is_ok() {
            ok += 1;
        }
        total += start.elapsed();
    }
    println!(
        "{label}: {:?}/op（{iters} 次，成功 {ok} 次，总 {total:?}）",
        total / iters
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("构建 current_thread runtime 失败");

    bench("帧解析 64B", 64, 20_000, &rt);
    bench("帧解析 4KB", 4 * 1024, 10_000, &rt);
    bench("帧解析 64KB", 64 * 1024, 2_000, &rt);
}
