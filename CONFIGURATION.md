# Rust FRP 配置说明

## 配置文件结构

Rust FRP 项目支持使用 TOML、YAML 或 JSON 格式的配置文件。以下是配置文件的基本结构：

### 服务器配置

```toml
# 服务器基本配置
bind_addr = "0.0.0.0"
bind_port = 7000
kcp_bind_port = 7001
quic_bind_port = 7002
vhost_http_port = 80
vhost_https_port = 443
tcpmux_http_connect_port = 10700

# Web 服务器配置
[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "admin"
tls = { enable = false }

# 认证配置
[auth]
method = "token"
token = "your_token"

# 传输配置
[transport]
protocol = "tcp"
tls = { enable = true, cert_file = "path/to/cert.pem", key_file = "path/to/key.pem" }
tcp_mux = true
pool_count = 10

# 端口范围配置
allow_ports = [
  { start = 1000, end = 2000 },
  { single = 8080 }
]

# 自定义 404 页面
custom_404_page = "path/to/404.html"

# 配置文件包含
includes = ["conf.d/*.toml"]
```

### 客户端配置

```toml
# 服务器连接配置
server_addr = "127.0.0.1"
server_port = 7000
user = "client"
client_id = "client_1"

# Web 服务器配置
[web_server]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "admin"
tls = { enable = false }

# 认证配置
[auth]
method = "token"
token = "your_token"

# 传输配置
[transport]
protocol = "tcp"
tls = { enable = true }
tcp_mux = true
pool_count = 10

# 代理配置
proxies = [
  { name = "tcp_proxy", type = "tcp", local_ip = "127.0.0.1", local_port = 8080, remote_port = 8080 },
  { name = "http_proxy", type = "http", local_ip = "127.0.0.1", local_port = 80, custom_domains = ["example.com"] }
]

# 访问者配置
visitors = [
  { name = "stcp_visitor", type = "stcp", server_name = "stcp_proxy", secret_key = "secret", bind_addr = "127.0.0.1", bind_port = 9000 }
]

# 配置文件包含
includes = ["conf.d/*.toml"]
```

## TLS 配置详解

### 1. 使用内置证书

当启用 TLS 但不指定证书文件时，系统会自动使用内置的自签名证书：

```toml
[transport]
tls = { enable = true }
```

内置证书位于 `rust_frp_net/cert/` 目录下，包括：
- `frp.crt`：自签名证书
- `frp.key`：私钥文件

### 2. 使用自定义证书

当启用 TLS 并指定证书文件时，系统会使用用户提供的证书：

```toml
[transport]
tls = { 
  enable = true, 
  cert_file = "path/to/cert.pem", 
  key_file = "path/to/key.pem",
  trusted_ca_file = "path/to/ca.pem",
  force = true
}
```

#### TLS 配置选项说明：
- `enable`：是否启用 TLS，布尔值
- `cert_file`：证书文件路径，可选（使用内置证书时不需要）
- `key_file`：私钥文件路径，可选（使用内置证书时不需要）
- `trusted_ca_file`：受信任的 CA 证书文件路径，可选
- `force`：是否强制使用 TLS，布尔值

## 其他配置选项说明

### 传输配置

```toml
[transport]
protocol = "tcp"  # 传输协议，可选值：tcp, kcp, quic
tls = { enable = true }  # TLS 配置
tcp_mux = true  # 是否启用 TCP 多路复用
pool_count = 10  # 连接池大小
bandwidth_limit = "10MB"  # 带宽限制，可选
```

### 认证配置

```toml
[auth]
method = "token"  # 认证方法，可选值：token, oidc
token = "your_token"  # 认证令牌noidc = {  # OIDC 认证配置
  issuer = "https://oidc.example.com",
  audience = "frp",
  client_id = "client_id",
  client_secret = "client_secret",
  token_endpoint_url = "https://oidc.example.com/token"
}
```

### Web 服务器配置

```toml
[web_server]
addr = "0.0.0.0"  # Web 服务器监听地址
port = 7500  # Web 服务器监听端口
user = "admin"  # Web 管理界面用户名
password = "admin"  # Web 管理界面密码
tls = { enable = false }  # Web 服务器 TLS 配置
```

### 代理配置

```toml
proxies = [
  # TCP 代理
  { 
    name = "tcp_proxy", 
    type = "tcp", 
    local_ip = "127.0.0.1", 
    local_port = 8080, 
    remote_port = 8080 
  },
  # HTTP 代理
  { 
    name = "http_proxy", 
    type = "http", 
    local_ip = "127.0.0.1", 
    local_port = 80, 
    custom_domains = ["example.com"],
    subdomain = "test",
    locations = ["/api"],
    host_header_rewrite = "localhost",
    http_user = "user",
    http_password = "pass"
  },
  # HTTPS 代理
  { 
    name = "https_proxy", 
    type = "https", 
    local_ip = "127.0.0.1", 
    local_port = 443, 
    custom_domains = ["example.com"]
  },
  # 插件代理
  { 
    name = "plugin_proxy", 
    type = "tcp", 
    local_ip = "127.0.0.1", 
    local_port = 8080, 
    remote_port = 8080,
    plugin = { 
      type = "unix_domain_socket", 
      unix_path = "/var/run/docker.sock" 
    }
  }
]
```

### 访问者配置

```toml
visitors = [
  # STCP 访问者
  { 
    name = "stcp_visitor", 
    type = "stcp", 
    server_name = "stcp_proxy", 
    secret_key = "secret", 
    bind_addr = "127.0.0.1", 
    bind_port = 9000 
  },
  # SUDP 访问者
  { 
    name = "sudp_visitor", 
    type = "sudp", 
    server_name = "sudp_proxy", 
    secret_key = "secret", 
    bind_addr = "127.0.0.1", 
    bind_port = 9001 
  }
]
```

## 配置文件包含

支持通过 `includes` 选项包含其他配置文件，方便管理多个配置：

```toml
includes = ["conf.d/*.toml", "conf.d/*.yaml"]
```

## 环境变量替换

配置文件支持环境变量替换，格式为 `${ENV_VAR}`：

```toml
[auth]
token = "${FRP_TOKEN}"
```

## 总结

Rust FRP 项目提供了灵活的配置选项，特别是在 TLS 配置方面，支持：
1. **内置自签名证书**：无需手动配置，启用 TLS 即可使用
2. **自定义证书**：可指定证书文件路径，满足生产环境需求
3. **多种配置格式**：支持 TOML、YAML、JSON 格式
4. **配置文件包含**：支持模块化配置管理
5. **环境变量替换**：支持从环境变量读取配置值

通过以上配置选项，可以根据不同的使用场景灵活配置 Rust FRP 服务。