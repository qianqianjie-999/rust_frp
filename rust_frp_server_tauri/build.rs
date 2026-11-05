fn main() {
    tauri_build::build();
    copy_webview2_loader();
}

/// 把 WebView2Loader.dll 复制到构建产物目录。
///
/// 背景：`webview2-com-sys` 只在 `target_env = "msvc"` 时静态链接
/// `WebView2LoaderStatic`，MinGW（`windows-gnu`）下走的是隐式动态导入
/// `WebView2Loader.dll`。缺少该 DLL 时进程在加载器阶段就失败，弹窗
/// “找不到 WebView2Loader.dll”，连日志都来不及写。
///
/// 本机 Windows 构建用的是 GNU 工具链（免装 VS），因此每次构建后都把
/// crate 自带的官方 x64 loader 放到 exe 同级目录。
fn copy_webview2_loader() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // MSVC 走静态链接，不需要外部 DLL。
        return;
    }
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        _ => return,
    };

    let out_dir = match std::env::var_os("OUT_DIR").map(std::path::PathBuf::from) {
        Some(dir) => dir,
        None => return,
    };
    // <profile>/build/<pkg>-<hash>/out -> <profile>/build -> <profile>
    let build_dir = match out_dir.ancestors().nth(2) {
        Some(dir) => dir.to_path_buf(),
        None => return,
    };
    let profile_dir = match build_dir.parent() {
        Some(dir) => dir.to_path_buf(),
        None => return,
    };

    // 首选：本次构建里 webview2-com-sys 自己拷出来的那份（版本必然匹配）。
    // 兜底：cargo registry 里 crate 源码自带的副本。
    let mut source = None;
    if let Ok(entries) = std::fs::read_dir(&build_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("webview2-com-sys-") {
                let candidate = entry
                    .path()
                    .join("out")
                    .join(arch)
                    .join("WebView2Loader.dll");
                if candidate.is_file() {
                    source = Some(candidate);
                    break;
                }
            }
        }
    }
    if source.is_none() {
        source = registry_loader(arch);
    }

    let source = match source {
        Some(path) => path,
        None => {
            println!(
                "cargo:warning=未找到 WebView2Loader.dll（{arch}），请手动复制到 exe 同目录，否则 GUI 无法启动"
            );
            return;
        }
    };
    let dest = profile_dir.join("WebView2Loader.dll");
    if dest.is_file() {
        return;
    }
    match std::fs::copy(&source, &dest) {
        Ok(_) => println!(
            "cargo:warning=已复制 WebView2Loader.dll -> {}",
            dest.display()
        ),
        Err(err) => println!(
            "cargo:warning=复制 WebView2Loader.dll 失败（{err}），请手动从 {} 复制到 exe 同目录",
            source.display()
        ),
    }
}

/// 在 cargo registry 源码目录里查找 `webview2-com-sys-*/<arch>/WebView2Loader.dll`。
fn registry_loader(arch: &str) -> Option<std::path::PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(|home| std::path::PathBuf::from(home).join(".cargo"))
        })?;
    let src_root = cargo_home.join("registry").join("src");
    for registry in std::fs::read_dir(src_root).ok()?.flatten() {
        let Ok(entries) = std::fs::read_dir(registry.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("webview2-com-sys-") {
                let candidate = entry.path().join(arch).join("WebView2Loader.dll");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
