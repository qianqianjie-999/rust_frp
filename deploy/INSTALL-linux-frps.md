# rust_frps v0.2.2 — Linux x86_64 安装指南（glibc 构建 (glibc ≥ 2.17)）

## 快速安装

```bash
sudo mkdir -p /opt/rust_frp/bin /opt/rust_frp/conf
sudo install -m 755 rust_frps /opt/rust_frp/bin/rust_frps
sudo cp frps.example.toml /opt/rust_frp/conf/frps.toml   # 按需修改
```

## systemd 服务（开机自启）

创建 `/etc/systemd/system/rust_frps.service`：

```ini
[Unit]
Description=Rust FRP Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/rust_frp/bin/rust_frps -c /opt/rust_frp/conf/frps.toml
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rust_frps     # enable = 开机自启
systemctl status rust_frps
```

## 常用命令

```bash
systemctl restart rust_frps          # 重启(改配置后)
journalctl -u rust_frps -f           # 实时日志
/opt/rust_frp/bin/rust_frps --version
```

## 升级

```bash
sudo systemctl stop rust_frps
sudo cp rust_frps.bak /opt/rust_frp/bin/   # 先备份旧文件
sudo install -m 755 rust_frps /opt/rust_frp/bin/rust_frps
sudo systemctl start rust_frps
```

注意：所有 frpc 客户端与服务端同版本升级，协议才保持一致。
