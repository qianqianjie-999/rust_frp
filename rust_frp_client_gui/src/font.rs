//! 中文字体加载
//!
//! egui 默认字体（Ubuntu/NotoEmoji）不含 CJK 字形，中文界面必须显式装载
//! 系统中文字体，否则全部渲染成豆腐块。
//!
//! 优先级：simhei.ttf（纯 TTF，绝大多数中文 Windows 都有）→ Deng.ttf →
//! NotoSansSC-VF.ttf → msyh.ttc / simsun.ttc（TTC，需抽取首个字体并重写
//! 表偏移——TTC 内各字体的表偏移是相对 TTC 文件头而非字体自身）。

use std::path::Path;

/// 尝试加载系统中文字体，返回可直接喂给 egui 的 sfnt 字节
pub fn load_cjk_font_bytes() -> Option<Vec<u8>> {
    const CANDIDATES: &[&str] = &[
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\Deng.ttf",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\NotoSansSC-VF.ttf",
    ];
    for path in CANDIDATES {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        if let Ok(bytes) = std::fs::read(p) {
            if let Some(sfnt) = to_standalone_sfnt(&bytes) {
                log::info!("GUI 中文字体: {} ({} 字节)", path, sfnt.len());
                return Some(sfnt);
            }
        }
    }
    log::warn!("未找到可用的中文字体，界面中文可能显示为方块");
    None
}

/// 普通 TTF/OTF 原样返回；TTC 抽取第一个字体并重写表偏移
fn to_standalone_sfnt(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    match &data[0..4] {
        b"\x00\x01\x00\x00" | b"OTTO" | b"true" | b"typ1" => return Some(data.to_vec()),
        b"ttcf" => {}
        _ => return None,
    }

    let num_fonts = be_u32(data, 8)?;
    if num_fonts == 0 {
        return None;
    }
    let first = be_u32(data, 12)? as usize;
    let end = if num_fonts > 1 {
        be_u32(data, 16)? as usize
    } else {
        data.len()
    };
    if first >= end || end > data.len() {
        return None;
    }

    let mut font = data[first..end].to_vec();
    let num_tables = be_u16(&font, 4)? as usize;
    let dir_len = 12 + 16 * num_tables;
    if dir_len > font.len() {
        return None;
    }

    // 判定表偏移基准：TTC 规范里表偏移相对 TTC 文件头（首个表应紧跟在
    // 本字体表目录之后，即偏移 ≈ first + dir_len）；若实测更接近 dir_len
    // 则已是字体相对偏移，无需改写。
    let first_off = be_u32(&font, 12 + 8)? as isize;
    let err_file_rel = (first_off - (first as isize + dir_len as isize)).abs();
    let err_font_rel = (first_off - dir_len as isize).abs();
    if err_file_rel >= err_font_rel {
        return Some(font);
    }

    for i in 0..num_tables {
        let rec = 12 + i * 16;
        let off = be_u32(&font, rec + 8)? as usize;
        if off >= first {
            let fixed = (off - first) as u32;
            font[rec + 8..rec + 12].copy_from_slice(&fixed.to_be_bytes());
        }
    }
    Some(font)
}

fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
