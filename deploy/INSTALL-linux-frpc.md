# rust_frpc v0.2.2 — Linux x86_64 安装指南（glibc 构建 (glibc ≥ 2.17)）

## 快速安装

```bash
sudo mkdir -p /opt/rust_frp/bin /opt/rust_frp/conf
sudo install -m 755 rust_frpc /opt/rust_frp/bin/rust_frpc
sudo cp frpc.example.toml /opt/rust_frp/conf/frpc.toml   # 按需修改(填 token/代理)
```

## systemd 服务（开机自启）

创建 `/etc/systemd/system/rust_frpc.service`：

```ini
[Unit]
Description=Rust FRP Client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/rust_frp/bin/rust_frpc -c /opt/rust_frp/conf/frpc.toml
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rust_frpc     # enable = 开机自启
systemctl status rust_frpc
```

## 常用命令

```bash
systemctl restart rust_frpc           # 重启(改配置后)
journalctl -u rust_frpc -f            # 实时日志
/opt/rust_frp/bin/rust_frpc --version
/opt/rust_frp/bin/rust_frpc verify -c /opt/rust_frp/conf/frpc.toml   # 离线校验配置
```

## STCP 场景注意

- 被访问端(owner)与访问端(visitor)的 `server_name` / `secret_key` 必须一致
- 客户端与服务端(frps)版本同步升级，新版要求 STCP 带 bridge_id

Windows 访客端见仓库 docs/windows-client.md。
