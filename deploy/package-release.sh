#!/usr/bin/env bash
# package-release.sh — 打 Release 二进制包(每个包内附安装文档)
# 用法: ./deploy/package-release.sh v0.2.2
# 前置: cargo build --release -p rust_frp_server -p rust_frp_client
#       ./deploy/windows/build-windows.sh
# 产物: dist/release/rust_*-<ver>-<平台>.* + SHA256SUMS.txt
set -euo pipefail
VER="${1:?用法: package-release.sh v0.2.2}"; VER="${VER#v}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/release"; T="$OUT/.tmp"
rm -rf "$T"; mkdir -p "$T/frps" "$T/frpc" "$T/win"
FRPS="$ROOT/target/release/rust_frps"; FRPC="$ROOT/target/release/rust_frpc"
WEXE="$ROOT/target/x86_64-pc-windows-gnu/release/rust_frpc.exe"
for b in "$FRPS" "$FRPC" "$WEXE"; do [ -x "$b" ] || { echo "[x] 缺 $b, 先构建"; exit 1; }; done
cp "$FRPS" "$T/frps/"; cp "$ROOT/frps.example.toml" "$T/frps/"; cp "$ROOT/deploy/INSTALL-linux-frps.md" "$T/frps/INSTALL.md"
tar -C "$T/frps" -czf "$OUT/rust_frps-$VER-linux-x86_64.tar.gz" rust_frps frps.example.toml INSTALL.md
cp "$FRPC" "$T/frpc/"; cp "$ROOT/frpc.example.toml" "$T/frpc/"; cp "$ROOT/deploy/INSTALL-linux-frpc.md" "$T/frpc/INSTALL.md"
tar -C "$T/frpc" -czf "$OUT/rust_frpc-$VER-linux-x86_64.tar.gz" rust_frpc frpc.example.toml INSTALL.md
cp "$WEXE" "$T/win/"
cp "$ROOT/deploy/windows/install.bat" "$ROOT/deploy/windows/uninstall.bat" "$ROOT/deploy/windows/update.bat" "$ROOT/deploy/windows/run.cmd" "$T/win/"
cp "$ROOT/deploy/windows/frpc.windows.example.toml" "$T/win/"
cp "$ROOT/docs/windows-client.md" "$T/win/INSTALL.md"
(cd "$T/win" && zip -q "$OUT/rust_frpc-$VER-windows-x86_64.zip" rust_frpc.exe install.bat uninstall.bat update.bat run.cmd frpc.windows.example.toml INSTALL.md)
(cd "$OUT" && sha256sum rust_*-"$VER"-* > SHA256SUMS.txt)
echo "[OK]"; ls -la "$OUT" | grep -E "rust_|SHA256"
