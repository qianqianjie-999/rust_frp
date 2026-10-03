# TLS 证书目录说明

本目录曾经存放随源码分发的内置自签证书 `frp.crt` / `frp.key`（通过
`include_bytes!` 内嵌进二进制）。

**已于 2026-10 移除**：服务端未配置证书时的兜底行为改为**运行时生成**
自签证书（`TlsConfig::new_server_with_runtime_cert()`，基于 `rcgen`）：

- 证书与私钥仅在内存中存在，不落盘、不入库，进程每次启动重新生成；
- 私钥不再随源码公开，拿到仓库的人无法据此伪造服务端身份；
- 仍为自签名证书，只提供加密不提供身份认证，启动时会打印 `WARN` 日志；
- 客户端未配置 `trusted_ca_file` 时跳过证书校验，同样打印 `WARN` 日志。

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
