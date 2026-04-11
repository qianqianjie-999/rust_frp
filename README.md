# Rust FRP

Rust FRP 是使用 Rust 语言重写的 FRP（Fast Reverse Proxy）项目，提供高效的反向代理功能。

## 功能特性

- **多协议支持**：TCP、UDP、HTTP、HTTPS
- **TLS 加密**：支持内置证书和自定义证书
- **Web 管理界面**：客户端 Web 管理界面，安全便捷
- **认证机制**：支持 Token 认证
- **配置管理**：支持 TOML、YAML、JSON 格式
- **插件系统**：支持多种插件扩展

## 项目结构

```
rust_frp/
├── rust_frp_core/      # 核心功能
├── rust_frp_server/    # 服务器端实现
├── rust_frp_client/    # 客户端实现
├── rust_frp_config/    # 配置管理
├── rust_frp_net/       # 网络通信
├── rust_frp_auth/      # 认证管理
├── rust_frp_plugin/    # 插件系统
├── rust_frp_util/      # 工具函数
├── frps.toml           # 服务器配置文件
├── frpc.toml           # 客户端配置文件
└── CONFIGURATION.md    # 配置说明文档
```

## 快速开始

### 1. 安装 Rust 工具链

```bash
# 访问 https://www.rust-lang.org/tools/install 下载并安装 Rust
```

### 2. 构建项目

```bash
cargo build
```

### 3. 运行服务器

```bash
cargo run --bin frps -- -c frps.toml
```

### 4. 运行客户端

```bash
cargo run --bin frpc -- -c frpc.toml
```

### 5. 访问客户端 Web 管理界面

```
http://localhost:7400
# 用户名: admin
# 密码: admin
```

## 配置说明

详细配置说明请参考 [CONFIGURATION.md](CONFIGURATION.md) 文件。

## TLS 配置

### 使用内置证书

```toml
[transport]
tls = { enable = true }
```

### 使用自定义证书

```toml
[transport]
tls = { enable = true, cert_file = "path/to/cert.pem", key_file = "path/to/key.pem" }
```

## 安全建议

- 禁用服务器端 Web 管理界面，只使用客户端 Web 管理界面
- 使用强密码保护客户端 Web 管理界面
- 启用 TLS 加密保护通信安全
- 定期更新配置和依赖

## 许可证

MIT License
