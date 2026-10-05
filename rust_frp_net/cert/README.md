# TLS 证书目录说明

本目录曾经存放随源码分发的内置自签证书 `frp.crt` / `frp.key`（通过
`include_bytes!` 内嵌进二进制）。

**已于 2026-10 移除**：服务端未配置证书时的兜底行为改为**运行时生成**
自签证书（`TlsConfig::new_server_with_runtime_cert()`，基于 `rcgen`）：

- 证书与私钥仅在内存中存在，不落盘、不入库，进程每次启动重新生成；
- 私钥不再随源码公开，拿到仓库的人无法据此伪造服务端身份；
- 仍为自签名证书，只提供加密不提供身份认证，启动时会打印 `WARN` 日志；
- 客户端证书校验为 **fail-closed**（2026-10-04 起）：配置了 TLS 但既无
  `trusted_ca_file` 又未显式 `skip_verify = true` 时，客户端**拒绝启动**；
  `skip_verify = true` 为显式跳过模式（仅加密、不认证，打印 WARN）。

## 生产环境应该怎么做

1. 用自己的 CA / 证书生成服务端证书与私钥，权限设为 `600`；
2. 服务端配置：

   ```toml
   [transport.tls]
   enable = true
   cert_file = "/etc/frp/certs/server.crt"
   key_file = "/etc/frp/certs/server.key"
   ```

3. 客户端配置 `trusted_ca_file` 固定信任该 CA：

   ```toml
   [transport.tls]
   enable = true
   trusted_ca_file = "/etc/frp/certs/ca.crt"
   ```

## mTLS（双向证书认证，2026-10-05 起支持）

要让"客户端身份"不再依赖共享 token，启用 mTLS：服务端校验客户端证书，
客户端出示自己的证书。**两个方向互不相同、都不可省**。

服务端（灰度期先 `require_client_cert = false`，铺开后再改 `true`）：

```toml
[transport.tls]
enable = true
cert_file = "/etc/frp/certs/server.crt"
key_file  = "/etc/frp/certs/server.key"
client_ca_file = "/etc/frp/certs/ca.crt"   # 校验客户端证书的 CA
require_client_cert = false                # false = 未出示也放行（过渡）
```

客户端（每机一张证书，`cert_file`/`key_file` 在此表示**客户端证书**）：

```toml
[transport.tls]
enable = true
trusted_ca_file = "/etc/frp/certs/ca.crt"   # 我验服务端
cert_file = "/etc/frp/certs/client-<主机>.crt"   # 服务端验我
key_file  = "/etc/frp/certs/client-<主机>.key"
```

签证书（用 `gen-client-certs.sh` —— **复用现有 CA**，不重建）：

```bash
CLIENTS="cli32 cli75" ./gen-client-certs.sh
# 产出 client-<名字>.crt/key（EKU = clientAuth，无 SAN）
```

> ⚠️ **不要用 `gen-certs.sh` 补签客户端证书**：它会**重建 CA**，导致线上已部署的
> `server.crt` / `client-*.crt` 全部失效并丢弃旧 CA 私钥；该脚本现在检测到已有 CA 时
> 会拒绝执行（需 `CA_FORCE=1`）。CA 材料备份见 `ca_backup.sh`。

⚠️ 三条硬约束：

- **没有"跳过 CA 校验"的开关**。一旦配 `client_ca_file` 就严格验链；
  `require_client_cert = false` 只放宽"是否允许**不出示**"，**不是**"不校验"。
- **客户端证书与 `skip_verify = true` 互斥**，配置校验直接拒绝：不校验服务端却
  出示证书，等于把身份递给可能冒充服务端的中间人。
- **`ca.key` 是最高价值资产**（拿到即可签发任意客户端证书，mTLS 归零）：
  必须离线备份，绝不下发到客户端。

灰度顺序与回滚：服务端先配 `client_ca_file`（`require = false`）→ 观察日志确认
各客户端均已出示 → 下发客户端证书 → 最后改 `require = true`；回滚只需把
`require_client_cert` 置回 `false` 并重启服务端。已覆盖 `tcp` / `websocket` / `wss` /
`quic`（QUIC 在 `quic.rs` 单独接线）；`kcp` 为明文 UDP，不受 mTLS 保护。

> 更新记录：2026-10-03 移除内置证书；2026-10-04 同步客户端 fail-closed 校验策略；
> 2026-10-05 生产环境完成 TLS 收口 —— 服务端改用自建 CA 签发的证书（SAN 含公网 IP），
> 客户端改用 `trusted_ca_file` 校验并移除 `skip_verify`，由"只加密"变为"真认证"。
> 2026-10-05 晚 支持 mTLS（`client_ca_file` / `require_client_cert`），
> 证书材料与轮换见 README「生产 TLS 证书」章节。
