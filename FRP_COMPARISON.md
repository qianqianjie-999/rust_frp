# rust_frp ↔ 原版 frp 能力对照报告

> 对照基线：`/home/qianqianjie/frp`（fatedier/frp，v0.71.0，commit `832df8d`）
> vs `/home/qianqianjie/rust_frp`（本地 master，`37fab80`）
> 报告日期：2026-10-04　｜　方法：**源码级逐项核对**（读双方源码/config struct/路由表，不采信 README 宣称）

---

## 〇、本次重核的说明（与旧版口径的差异）

旧版报告采用 **44 项粗粒度口径**，把「管理 API」「插件体系」各记作 1~2 项，且对
「部分实现 / 计划落地」的项偏宽松，得出 95%（43/44）。本次重核改为
**按可验证的最小能力单元计分**（单个传输协议、单个客户端插件、单个 API 端点、
单类配置项各记 1 项），并只对「确实可用」的项记分。因此：

- 数字由 95% 下调至 **≈68%**，**不代表功能退化**，而是度量更细、更严格；
- 旧版把「代理类型 9/9、传输 8/8、管理 API 4/4、CLI 3/3」记满，本次核对后确认
  其中 **wire v2、frps 大半 API、frpc stop/nathole/子命令、Store、vnet、
  additionalScopes、SSH 隧道、tracer** 等均未落地，属实打实的缺口。

> 一句话：**数据面已基本对齐，控制面/运维面仍偏瘦。**这与旧版结论方向一致，但差距幅度此前被低估。

---

## 一、一页纸摘要

| 指标 | rust_frp | frp 0.71 | 结论 |
|------|---------|----------|------|
| 语言 / 构建 | Rust（cargo workspace，8 crate） | Go（单 module） | — |
| 核心代码量 | ~19,000 行 | ~57,400 行（不含 web） | rust 约为原版 **1/3** |
| 单元测试 | ~322 个 | ~300 个 `Test` 函数 | 基本相当 |
| 能力覆盖率 | **≈ 77%（56/73）** ｜ 数据面 **92%（24/26）**、控制/运维面 **68%（32/47）** | 100%（基线） | 见第二节 |
| 配置字段兼容 | ⚠️ 双向 alias 兼容，但**约 25+ 个原版字段未支持**（解析成功 + WARN） | camelCase + 严格模式 | 原版配置**可加载**但部分字段不生效 |
| 管理前端 | 原生 HTML/JS（内嵌） | Vue 3 + TS + Element Plus | 原版更强 |
| CLI 子命令 | verify / reload / status | reload / status / stop / verify / nathole / 每类代理 | rust 明显偏少 |
| 安全默认值 | ✅ 更保守（见第九节） | 一般 | **rust 更严** |
| 运行时依赖 | rustls/ring + quinn（无 OpenSSL、无 C 依赖） | golib/quic-go/kcp-go | 均为单二进制 |

**一句话结论**：rust_frp 的**数据面（data plane）已基本对齐**（代理类型、TLS/KCP/QUIC/WebSocket
传输、应用层加密与压缩、STCP/XTCP 打洞、负载均衡、限速、连接池、热重载、优雅关闭全部可用）；
**控制面/运维面（控制 API、CLI、插件覆盖面、认证扩展、配置字段）覆盖约 68%**，
缺口集中在「运维丰富度」与「少数生态特性」，而非「能不能用」。

---

## 二、能力覆盖计分卡（73 项口径）

| 分类 | 覆盖 | 覆盖率 | 主要缺口 |
|------|:----:|:------:|----------|
| 代理类型 | **8/8** | 100% | —（rust 另多 1 种 `websocket` 代理类型） |
| 传输协议 | **5/5** | 100% | —（`wss` 已落地，见 五、传输与协议对照） |
| 内部线协议 | **1/2** | 50% | wire protocol v2（魔数分帧 + AEAD + 能力协商） |
| 数据面能力 | **10/11** | 91% | PROXY protocol v2（rust 仅 v1 布尔开关） |
| 客户端插件 | **7/10** | 70% | `http2http`、`http2https`、`virtual_net`（`http_proxy`/`socks5` 认证已强制；`http_proxy` 仍仅支持 CONNECT） |
| 服务端插件 | **1/2** | 50% | tracer 链路追踪 |
| 认证与安全 | **4/7** | 57% | `additionalScopes`、SSH 隧道网关、FeatureGate/`--allow-unsafe` |
| frps 管理 API | **9/9** | 100% | —（v1 serverinfo/clients/按类型名称查询/流量 + v2 套件/分页/prune/users + DELETE offline 全部落地） |
| frpc 管理 API | **3/5** | 60% | `/api/stop`、Store 源代理 CRUD |
| CLI | **4/8** | 50% | `stop`、`nathole`、每类代理/访客子命令、`--config_dir` |
| 配置体系 | **4/6** | 67% | Store 配置源、FeatureGates |
| **合计** | **56/73** | **≈77%** | — |

**分组小结**：

| 分组 | 覆盖 | 说明 |
|------|:----:|------|
| 数据面 / 协议（代理类型 + 传输 + 线协议 + 数据面能力） | **24/26（92%）** | 转发链路基本对齐 |
| 控制 / 运维面（插件 + 认证 + API + CLI + 配置） | **32/47（68%）** | 运维丰富度差距明显 |

> 计分口径：一项能力「确实可用且与原版等价（或更强）」记 1 分；缺失 / 仅占位 / 显著弱化 / 未强制记 0 分。

---

## 三、规模与结构对照

| 维度 | rust_frp | frp 0.71 |
|------|----------|----------|
| 模块组织 | 8 个 crate 分包（core/net/auth/config/plugin/server/client/util） | pkg/ 下 17 个子包 + client/ + server/ 顶层 |
| 服务端 | `rust_frp_server` 拆 10 个子模块 | `server/`（control/proxy/group/ports/registry/http/metrics…） |
| 客户端 | `rust_frp_client` 单文件为主 + `src/bin/rust_frpc.rs` | `client/`（control/proxy/visitor/health/configmgmt/http…） |
| 二进制 | `rust_frpc` / `rust_frps` | `frpc` / `frps` |
| 前端构建 | 无（`include_str!` 内嵌 `web_ui.html`） | Vite 构建，`web/frpc` + `web/frps` + `web/shared` |
| 配置体系 | 单份 TOML/YAML/JSON（+ 兼容层） | 双体系：`config/legacy`（INI）+ `config/v1`（TOML/YAML/JSON） |
| 线协议 | 单一：`[4B 大端长度][JSON]`（≈原版 v1） | **双版本**：v1（类型字节+JSON）与 v2（魔数分帧+AEAD+能力协商） |

---

## 四、代理类型对照

| 代理类型 | rust_frp | frp 0.71 | 备注 |
|----------|:--------:|:--------:|------|
| tcp | ✅ | ✅ | 等价 |
| udp | ✅ | ✅ | 等价 |
| http | ✅ | ✅ | rust 缺 `RequestHeaders`/`ResponseHeaders`/`RouteByHTTPUser` 等细粒度字段 |
| https | ✅ | ✅ | 等价 |
| stcp | ✅ | ✅ | rust 有 `secret_key` HMAC 签名 + 跨客户端；`allowUsers` 亦支持 |
| xtcp | ✅ | ✅ | rust 为 STUN + KCP 真打洞，失败回退 STCP；原版默认 QUIC 打洞，模式更全 |
| tcpmux | ✅ | ✅ | HTTP CONNECT 复用 + 域名/HTTP 用户路由 |
| sudp | ✅ | ✅ | 与 stcp 同构的隧道承载 UDP；访问端按源地址建独立会话 |
| **websocket** | ✅（rust 特有） | ❌（仅作传输协议） | rust 把 websocket 也当代理 type，原版无此代理类型 |

> **净差**：代理类型已 **8/8 对齐**；rust 另多 1 种自定义用法。

---

## 五、传输与协议对照

| 传输/协议 | rust_frp | frp 0.71 | 备注 |
|-----------|:--------:|:--------:|------|
| tcp | ✅ | ✅ | — |
| kcp | ✅ | ✅ | rust 自研 `kcp_stream.rs`；原版用 `xtaci/kcp-go` |
| quic | ✅ | ✅ | rust 基于 quinn 0.11（TLS 1.3 强制），单 UDP 连接多路复用控制+工作连接 |
| websocket | ✅ | ✅ | rust 有 `WebSocketConn` / `accept_websocket` |
| **wss** | ✅ | ✅ | rust：TLS 之上叠加 WebSocket（路径 `/~!frp`），服务端在 TLS 握手后嗅探升级；fail-closed 要求信任来源 |
| **wire protocol v2** | ❌ | ✅ | 原版 `pkg/proto/wire`（能力协商 + AEAD aes-256-gcm/xchacha20） |
| tcp_mux | ✅ | ✅ | rust `mux.rs`（魔数 `0x5A`）；原版 wire v1 内置 |
| TLS 默认加密 | ✅（默认 on） | ✅（默认 on） | 双方无证书时均**运行时自签** |
| TLS force / 仅 TLS | ✅ `tls_only` | ✅ `transport.tls.force` | 等价 |
| TLS 客户端校验 | ✅ fail-closed（无 CA 且未显式 skip → 拒绝启动） | ⚠️ 有 TrustedCAFile 才 force | **rust 更严** |
| 应用层加密 `use_encryption` | ✅ AES-256-GCM（自研帧） | ✅ libio WithEncryption | 双方均已实现 |
| 应用层压缩 `use_compression` | ✅ snappy（raw block，可与加密叠加） | ✅ snappy | 等价 |

---

## 六、数据面能力对照

| 能力 | rust_frp | frp 0.71 | 备注 |
|------|:--------:|:--------:|------|
| 负载均衡 / 分组（group + groupKey） | ✅ | ✅ | 等价（round-robin；组密钥校验防误入） |
| 健康检查（tcp / http） | ✅ | ✅ | 等价 |
| 带宽限速（全局 + 代理级） | ✅ | ✅ | rust 经 `sanitize_rate` 规整 |
| 工作连接池（poolCount） | ✅ | ✅ | 等价 |
| 配置热重载 | ✅ | ✅ | SIGHUP / 文件监听 / API / frpc reload |
| 优雅关闭 | ✅ | ✅ | rust 停止 accept + 排空存量连接（10s 上限） |
| PROXY protocol | ⚠️ **仅 v1** | ✅ v1 + v2 | rust 为布尔开关，v2 未实现 |
| 流量统计 | ✅ | ✅ | rust 桥接结束累加双向字节，服务端 + Prometheus + frpc status 暴露 |

> 计分中「数据面能力 10/11」即上表 11 项里 PROXY protocol 因仅 v1 记 0。

---

## 七、插件体系对照

**客户端插件（原版 10 个）**

| 插件 | rust_frp | frp 0.71 | 备注 |
|------|:--------:|:--------:|------|
| unix_domain_socket | ✅ | ✅ | 等价 |
| static_file | ✅（含路径遍历防护 + Basic Auth） | ✅（gorilla/mux） | rust 安全加固更强 |
| http_proxy | ✅（认证已强制） | ✅ | rust 校验 `Proxy-Authorization: Basic`（常量时间），失败 407；**仅支持 CONNECT**，普通 HTTP 转发未实现 |
| socks5 | ✅（认证已强制，已支持 IPv6） | ✅（支持认证 + IPv6） | rust 按 RFC 1929 校验 `username`/`password`（常量时间）；本轮补齐 IPv6 |
| https2http | ✅（`TlsOffloadPlugin`） | ✅ | 等价 |
| tls2raw | ✅（与 https2http 同实现） | ✅ | 等价 |
| https2https | ✅（`TlsBridgePlugin`） | ✅ | 等价 |
| **http2http** | ❌ | ✅ | 接受 h2c 访客 → 本地 HTTP/1.1 |
| **http2https** | ❌ | ✅ | 接受 h2c 访客 → 本地 HTTPS |
| **virtual_net** | ❌ | ✅（配合 pkg/vnet） | 虚拟网络插件 |

> ✅ **已修复**：`http_proxy` / `socks5` 的插件级认证**已强制**（凭据常量时间比较），
> 未配置凭据时保持匿名 / 无认证语义（与原版一致）。

**服务端插件**

| 能力 | rust_frp | frp 0.71 |
|------|:--------:|:--------:|
| 服务端插件机制 | ✅ `rust_frp_plugin::server_plugin` | ✅ `plugin/server/manager` |
| 通用 HTTP 回调插件（6 类钩子） | ✅ Login/NewProxy/CloseProxy/Ping/NewWorkConn/NewUserConn（含 reject / unchange 覆写） | ✅ 同名六类钩子 |
| **链路追踪 tracer** | ❌ | ✅ |

---

## 八、认证与安全对照

| 能力 | rust_frp | frp 0.71 | 备注 |
|------|:--------:|:--------:|------|
| token 认证 | ✅ | ✅ | 双方常量时间比较 |
| 工作连接签名 | ✅ HMAC-SHA256 + run_id | ✅ `GetAuthKey(token,ts)` | 等价（rust fail-closed：配了 token 就强制验签） |
| OIDC 认证 | ✅ | ✅ 完整 | rust：Discovery + JWKS + RS256/ES256 验签 + 客户端 `client_credentials` |
| tokenSource（file/exec 动态取 token） | ✅ | ✅ | 与静态 `token` 互斥，解析结果仅存内存 |
| **auth additionalScopes** | ❌ | ✅ HeartBeats / NewWorkConns | 原版会在心跳/新工作连接上追加刷新令牌 |
| **SSH 隧道网关** | ❌ | ✅ `SSHTunnelGateway`（forwarded-tcpip） | 原版独有 |
| **FeatureGate / `--allow-unsafe`** | ❌ | ✅ | 原版独有 |
| 登录防爆破 | ✅ 5 次失败锁 5 分钟 | ❌ 无 | **rust 更严** |
| Dashboard 会话 | ✅ 随机令牌 + 8h TTL + HttpOnly/SameSite | ✅ Basic Auth | rust 更强 |
| 端口白名单默认拒绝 | ✅ 默认空 = 拒绝所有端口 | ⚠️ 默认放开 | **rust 更严** |

---

## 九、管理面（frps API / frpc API / CLI）对照

### 9.1 frps HTTP API

| 端点 | rust_frp | frp 0.71 |
|------|:--------:|:--------:|
| `/health` / `/healthz` | ✅ | ✅ |
| `/metrics`（Prometheus） | ✅（默认关） | ✅（默认关） |
| `/api/proxies`（列表，含 `traffic_in/out`） | ✅ | ✅ |
| `/api/proxy/{type}`、`/api/proxy/{type}/{name}`、`/api/proxies/{name}`（按类型/名称详情） | ✅ | ✅ |
| `/api/traffic/{name}`（单代理流量，24h 序列） | ✅ | ✅ |
| `/api/serverinfo`（服务器信息） | ✅ | ✅ |
| `/api/clients`、`/api/clients/{key}`（客户端列表/详情，含离线历史） | ✅ | ✅ |
| `DELETE /api/proxies?status=offline`（离线清理） | ✅ | ✅ |
| `/api/v2/*`（system info/prune、clients、proxies 套件 + 分页信封） | ✅ | ✅ |
| `/api/v2/users`（用户管理/聚合） | ✅ | ✅ |

> `key = base64url(user|clientId|runId)`，与原版一致；v2 分页 `page`/`pageSize`
> 默认 1/50、上限 200，越界或非法 `status` 返回 400。

### 9.2 frpc HTTP API（管理端口）

| 端点 | rust_frp | frp 0.71 |
|------|:--------:|:--------:|
| reload | ✅ `POST /reload` | ✅ `GET /api/reload` |
| status | ✅ `GET /status` | ✅ `GET /api/status` |
| stop | ❌ | ✅ `POST /api/stop` |
| config 读取/写入 | ✅ `GET/PUT /config` | ✅ `GET/PUT /api/config` |
| 单代理/访客配置查询 | ❌ | ✅ `/api/proxy/{name}/config`、`/api/visitor/{name}/config` |
| Store 源代理/访客 CRUD | ❌ | ✅ `/api/store/proxies`、`/api/store/visitors`（Create/Get/Update/Delete） |

### 9.3 CLI 子命令

| 命令 | rust_frp | frp 0.71 |
|------|:--------:|:--------:|
| 启动（`-c config`） | ✅ | ✅ |
| `frpc reload` / `status` | ✅ | ✅ |
| `frpc stop` | ❌ | ✅ |
| `frpc verify`（配置校验） | ✅ | ✅ |
| `frpc nathole discover`（打洞调试） | ❌ | ✅ |
| 每类代理子命令（`frpc tcp/udp/http/…`） | ❌ | ✅（8 类 + 访客子命令） |
| `--config_dir`（多实例） | ❌ | ✅ |
| `--strict_config`（未知字段即报错，默认 true） | ❌（rust 为 WARN 模式） | ✅ |

---

## 十、配置体系对照（含字段级缺口）

**体系能力**

| 能力 | rust_frp | frp 0.71 |
|------|:--------:|:--------:|
| TOML / YAML / JSON | ✅ | ✅ |
| camelCase / snake_case 双向兼容 | ✅（serde alias） | 仅 camelCase |
| `includes`（多文件） | ✅ | ✅ |
| 环境变量替换（`${VAR}`） | ✅ | ✅（模板渲染） |
| **Store 配置源**（内置 CRUD 存储） | ❌ | ✅ |
| **FeatureGates** | ❌ | ✅ |

**原版字段中 rust 未支持（会被 WARN 忽略）的部分**

| 侧 | 缺失字段（原版有，rust 无） |
|----|------------------------------|
| frps | `vhostHTTPTimeout`、`subDomainHost`（rust 用 `subdomain_base`）、`tcpmuxPassthrough`、`detailedErrorsToClient`、`userConnTimeout`、`maxPortsPerClient`（rust 用 `maxPortsPerUser`，命名不同）、`natholeAnalysisDataReserveHours`、`udpPacketSize`、`sshTunnelGateway`、`featureGates`、`auth.additionalScopes`、`transport.heartbeatTimeout`/`tcpKeepalive`/`maxPoolCount` |
| frpc | `natHoleStunServer`、`dnsServer`、`loginFailExit`、`start`（按名启用代理）、`udpPacketSize`、`virtualNet`、`featureGates`、`store`、`auth.additionalScopes`、`transport.wireProtocol`/`proxyURL`/`connectServerLocalIP`/`dialServerTimeout`/`dialServerKeepalive`/`tcpMuxKeepaliveInterval`/`heartbeatInterval`/`heartbeatTimeout` |
| 代理 | HTTP/HTTPS：`requestHeaders`、`responseHeaders`、`routeByHTTPUser`；PROXY protocol v2 |

> 兼容策略差异：原版 `--strict_config` 默认 **true**（未知字段直接报错）；rust 采取
> **解析成功 + 逐字段 WARN**（迁移更平滑，但需用户自查日志确认字段是否生效）。

---

## 十一、rust_frp 更严格 / 更优的项（保留优势）

1. **安全默认值更保守**：端口白名单默认「空即拒绝」；`web_server.user/password` 不成对则拒绝启动；TLS fail-closed；`/metrics` 默认关闭；Dashboard 登录 5 次失败锁 5 分钟。
2. **无 C 依赖**：rustls/ring + quinn（`rustls-ring` backend），无 OpenSSL、无 `aws-lc-rs`，Alpine/musl 天然友好。
3. **内存安全 + 无 GC**：Rust 所有权模型，无 STW 停顿。
4. **TLS 客户端校验 fail-closed**：原版「未配 CA 时是否校验」语义弱于 rust 的显式拒绝。
5. **代码量仅 1/3**：19k vs 57k 行，服务端拆 10 模块，可读性更高。
6. **静态文件插件含路径遍历防护**；**常量时间**凭据比较贯穿认证链路（含 `http_proxy`/`socks5` 插件级认证）；**工作连接签名 fail-closed**。

---

## 十二、差距清单（按优先级）

### P0 — 影响「数据正确 / 用户预期」
| # | 缺口 | 说明 |
|---|------|------|
| 1 | ~~配置字段命名 snake_case vs camelCase~~ | ✅ 已落地（alias 双向兼容，原版配置可加载） |
| 2 | 未知字段不报错（WARN 模式） | ⚠️ 设计取舍：硬拒绝会误杀原版配置；需用户自查日志 |
| 3 | ~~无 `frpc reload/status/verify`~~ | ✅ 已落地 |
| 4 | ~~无代理 CRUD / frpc 管理 API~~ | ✅ 已落地（`GET/PUT /config`） |

### P1 — 能力/运维缺口（功能对不齐）
| # | 缺口 | 现状 |
|---|------|------|
| 5 | ~~QUIC 传输~~ | ✅ 已落地（quinn 0.11 + rustls-ring，TLS 1.3 强制、fail-closed） |
| 6 | ~~`use_compression` 压缩~~ | ✅ 已落地（snappy） |
| 7 | ~~OIDC 完整流程~~ | ✅ 已落地（Discovery + JWKS + RS256/ES256）。**残留**：`additionalScopes` 未做 |
| 8 | ~~tcpmux 代理~~ | ✅ 已落地 |
| 9 | ~~sudp 代理~~ | ✅ 已落地 |
| 10 | ~~服务端插件机制~~ | ✅ 已落地（6 类回调钩子）。**残留**：tracer 未做 |
| 11 | ~~优雅关闭~~ | ✅ 已落地 |
| 12 | ~~流量统计~~ | ✅ 已落地 |
| 13 | ~~`http_proxy`/`socks5` 插件级认证未强制~~ | ✅ 已落地（http_proxy → 407；socks5 → RFC 1929）。**残留**：`http_proxy` 仅支持 CONNECT |
| 14 | ~~`wss` 传输~~ | ✅ 已落地（TLS + WebSocket，`/~!frp` 路径，双端嗅探升级；3 个 e2e 测试） |
| 15 | **frpc `stop` / `nathole` / 每类代理子命令 / `--config_dir`** | ❌ CLI 面偏瘦 |
| 16 | ~~frps API 补齐~~（serverinfo / 按类型名称查询 / clients / v2 套件 / DELETE offline） | ✅ 已落地（v1 全端点 + v2 `{code,msg,data}` 信封 + 分页 + prune + users 聚合） |
| 17 | **wire protocol v2** | ❌ 线协议仍为 v1 等价实现 |

### P2 — 生态 / 增强项（非必需）
`http2http`、`http2https`、`virtual_net`（vnet）、`pkg/sdk` 进程内嵌库、SSH 隧道网关、
Store 配置源 + StoreProxy CRUD、FeatureGates、`--strict_config`、端口保留（断线 24h）、
PROXY protocol v2、`dnsServer`、`natHoleStunServer`、`loginFailExit`、`start`、
`udpPacketSize`、`metadatas` 之外的元数据、服务端带宽限制模式、legacy INI 配置。

---

## 十三、结论与建议路线

**定位判断**：rust_frp 的**数据面已基本对齐**——TCP/UDP/HTTP/HTTPS/STCP/XTCP/tcpmux/sudp
转发、TLS/KCP/QUIC/WebSocket/WSS 传输、AES-256-GCM 应用层加密、snappy 压缩、STUN 真打洞、
负载均衡、健康检查、限速、连接池、配置热重载、优雅关闭全部可用。
**控制面/运维面覆盖约 68%**，缺口以「运维丰富度」和「少数生态特性」为主，
**且已无阻塞使用的硬缺口**（P0 全部落地、P1 核心项落地）。

**建议路线（按投入产出排序）**：
1. ~~**`wss` 传输**~~ —— ✅ 已完成（复用 websocket+TLS 代码 + 服务端嗅探升级）。
2. ~~**frps API 补齐**（serverinfo、按类型/名称查询、clients、DELETE offline）~~ —— ✅ 已完成（v1 + v2 套件、分页信封、离线历史）。
3. **frpc CLI 补齐**（`stop`、`--config_dir`）—— 运维便捷性。
4. **`http2http` / `http2https` 插件** —— 引入 `h2`，自包含在插件 crate。
5. **`http_proxy` 普通 HTTP 转发** —— 补齐与原版的最后一处插件语义差异。
6. **wire protocol v2** —— 最大项，改线格式、回归风险高，建议放最后。

> ✅ 已完成：`http_proxy` / `socks5` 插件级认证；`wss` 传输（原建议路线第 1 项）；
> **frps 管理 API 补齐**（原建议路线第 2 项）。

**不建议盲目对齐的项**：vnet 虚拟网络、in-process SDK、SSH 隧道网关、FeatureGates——
属原版「生态扩展」，除非有明确场景，否则投入产出比低。

---

## 附：本次重核的方法与口径

- 对照对象为**实际源码**：原版 `pkg/config/v1/*.go`（配置结构）、`server/api_router.go`、`client/api_router.go`、
  `cmd/frpc/sub/*.go`（CLI）、`pkg/plugin/client/*.go`（插件）；rust 侧对应 `rust_frp_config/src/lib.rs`、
  `rust_frp_server/src/web.rs`、`rust_frp_client/src/bin/rust_frpc.rs`、`rust_frp_plugin/src/lib.rs`。
- 计分单元 = 可独立验证的最小能力（1 个传输协议 / 1 个插件 / 1 个 API 端点 / 1 类配置项）。
- 本次同步删除的陈旧内容：`README.md` 中「全部功能已实现」的绝对化表述已修正；本报告旧版的
  「文档修正」变更流水账已移除（历史提交记录即可追溯）；源码中「路线图配置项」占位字段与注释已清理。
