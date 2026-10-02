# 内置 TLS 证书说明（⚠️ 不安全，仅供开发）

本目录下的 `frp.crt` / `frp.key` 是**随源码公开分发**的自签名证书与私钥，
通过 `include_bytes!` 内嵌进二进制，用于「服务端未显式配置证书」时的兜底。

## 为什么它是不安全的

私钥在版本库里公开，意味着**任何拿到本仓库的人都能伪造服务端身份**。
因此这组证书只提供传输加密，**不提供任何身份认证能力**。

- 服务端在使用内置证书启动时会打印 `WARN` 日志；
- 客户端在未配置 `trusted_ca_file` 时同样会收到 `WARN` 日志，提示证书未被校验。

## 生产环境应该怎么做

1. 用自己的 CA / 证书，生成服务端证书与私钥，权限设为 `600`；
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

> 后续计划：把内置证书改为**运行时在数据目录自动生成**（首次启动时创建，
> 私钥不入库），彻底消除「公开私钥」问题。该改动需要引入证书生成依赖
> （如 `rcgen`），当前环境离线无法拉取，故暂缓。
