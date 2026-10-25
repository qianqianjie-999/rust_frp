//! 程序化生成托盘/窗口图标（32x32 RGBA，无图片依赖）
//!
//! 颜色语义：绿=已连接，琥珀=启动中/重连中，灰=已停止/错误。

use crate::client_runtime::ConnState;
use tray_icon::Icon;

const SIZE: usize = 32;

/// 按连接状态生成托盘图标
pub fn status_icon(state: &ConnState) -> Icon {
    let (r, g, b) = match state {
        ConnState::Connected => (34, 197, 94),
        ConnState::Starting | ConnState::Reconnecting => (245, 158, 11),
        ConnState::Stopped | ConnState::Error(_) => (156, 163, 175),
    };
    let (rgba, width, height) = circle_rgba(r, g, b);
    Icon::from_rgba(rgba, width, height).expect("程序化生成的图标必然合法")
}

/// 生成一个实心圆 + 白边图标的原始 RGBA 像素
pub fn circle_rgba(r: u8, g: u8, b: u8) -> (Vec<u8>, u32, u32) {
    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    let center = (SIZE as f32 - 1.0) / 2.0;
    let fill_radius = 12.5f32;
    let ring_radius = 15.0f32;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let i = (y * SIZE + x) * 4;
            if dist <= fill_radius {
                rgba[i] = r;
                rgba[i + 1] = g;
                rgba[i + 2] = b;
                rgba[i + 3] = 255;
            } else if dist <= ring_radius {
                rgba[i] = 255;
                rgba[i + 1] = 255;
                rgba[i + 2] = 255;
                rgba[i + 3] = 255;
            }
        }
    }
    (rgba, SIZE as u32, SIZE as u32)
}

/// 窗口标题栏图标（egui::IconData）
pub fn window_icon() -> egui::IconData {
    let (rgba, width, height) = circle_rgba(34, 197, 94);
    egui::IconData {
        rgba,
        width,
        height,
    }
}
