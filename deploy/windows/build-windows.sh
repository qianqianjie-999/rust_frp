#!/usr/bin/env bash
# ============================================================================
# build-windows.sh — 在 Linux 构建机(C32)上交叉编译 rust_frpc.exe (Windows x64)
# 用法: ./build-windows.sh [输出目录]   (默认输出到 ./dist/)
# 依赖: mingw64-gcc (dnf install -y mingw64-gcc)
#       rustup target add x86_64-pc-windows-gnu
# ============================================================================
set -euo pipefail

OUT="${1:-dist}"
TARGET=x86_64-pc-windows-gnu

# mingw 链接器路径
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc

echo "[*] rustc: $(rustc --version)"
echo "[*] mingw: $(x86_64-w64-mingw32-gcc --version | head -1)"

# release profile: 减小体积; panic=abort 与服务端/Linux 端保持一致
export RUSTFLAGS="-C panic=abort"
cargo build --release --target "$TARGET" -p rust_frp_client

BIN="target/$TARGET/release/rust_frpc.exe"
mkdir -p "$OUT"
cp "$BIN" "$OUT/rust_frpc.exe"
echo "[OK] $OUT/rust_frpc.exe ($(stat -c%s "$OUT/rust_frpc.exe") bytes)"
sha256sum "$OUT/rust_frpc.exe"
echo "[*] 传回 Windows 后: certutil -hashfile rust_frpc.exe SHA256 核对一致再用"
