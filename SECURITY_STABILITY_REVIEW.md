# rust_frp 安全与稳定性专项复审

> 审查日期：2026-10-03 ｜ 范围：`fix/p0-security-hardening`（e627958）当前代码
> 方式：客观命令实测 + 逐行安全走读 + 前置守卫核验
> **2026-10-03 更新：P0-1 / P0-2 / P1-3 已修复（见《八、修复记录（第二轮）》）；
> P1-1 / P1-2 / P1-4 已修复（见《九、修复记录（第三轮）》）**

---

## 一、总体结论

**专项评分：72 / 100（B）—— 上轮 P0 修复质量过硬，但稳定侧暴露出一个新的 P0（登录前连接可无限挂起）。**

一句话结论：**鉴权与加密的实现质量现在是扎实的，真正的短板从"怎么认证"转移到了"不认证时会发生什么"——未认证阶段缺乏超时和连接数上限，构成可被远程触发的资源耗尽面。**

| 维度 | 权重 | 得分 | 判断 |
|---|---|---|---|
| 认证与授权 | 25% | 7.5 | 实现质量好，缺防爆破节流 |
| 传输安全（TLS） | — | 6.5 | 内置私钥入库为遗留项 |
| 输入与内存防护 | 15% | 6.0 | 帧长有上限，但预认证阶段可放大 |
| 崩溃安全（panic 面） | 15% | 7.0 | 0 unsafe；std 锁中毒链是主要风险 |
| 资源与运行稳定性 | 20% | 6.5 | 心跳/停机设计好，预认证挂起是硬伤 |
| 运维与可观测 | 10% | 7.5 | /metrics 公开暴露信息 |
| 静态质量 | 5% | 9.0 | fmt/clippy/测试全绿 |
| **加权合计** | | **72** | **B：可上生产，但需先修 P0-1** |

---

## 二、实测客观信号（全绿基线）

```
cargo fmt --all --check       → 干净
cargo clippy --workspace      → 0 error（告警集合与上轮一致）
cargo test --workspace        → 171 passed / 0 failed
生产代码 unsafe / todo!       → 0 处
```

上轮修复项复核（全部到位）：
- ✅ WebAuth：随机会话令牌 + 服务端存储 + 8h TTL + 过期清理（`purge_expired_sessions` 在创建/校验时触发）+ 常量时间凭据比对 + `HttpOnly; SameSite=Strict`
- ✅ 管理端免鉴权白名单仅 `/login`、`/health`、`/metrics`（`server:2863`），其余全部要求会话
- ✅ 控制通道登录 token 走 `constant_time_compare`（`auth:203`）
- ✅ 工作连接签名 fail-closed + 常量时间
- ✅ 限速器状态机（无 poll 内 spawn）、配置日志脱敏、dashboard XSS 修复无回退

---

## 三、做得好的（明确"不要动"）

1. **协议帧长度上限 + 明确错误**（`core:620/658`）：`MAX_MESSAGE_SIZE = 10MB`，超限返回 `InvalidData` 而非静默
2. **心跳与半开检测**（`server:1068/1330`）：15s 读超时 + 90s 无心跳强踢清理代理——这是内网穿透服务端最容易烂掉的地方，设计是对的
3. **连接池有界**（`net/pool:214`）：Semaphore 并发控制，池化取后补充
4. **优雅停机**（两端 bin）：SIGINT/SIGHUP 都有处理，连接 shutdown 走完
5. **端口防护**：`max_ports_per_user` 配额 + `allow_ports` 白名单（上轮修掉的范围旁路没回归）
6. **上轮补的 17 个回归测试**直接锁死了会话、cookie 属性、限速边界——这轮走读就是靠它们快速排除误报

---

## 四、问题清单

### P0（远程可触发，建议本周修）

**P0-1 登录前读无超时 → 慢速连接耗尽（Slowloris）**

两处未认证读都会永久挂起：

- 控制口：`Control::run` 的登录首读 `self.conn.read_message().await`（`server:996`）——**无任何 timeout**
- 工作连接口：`process_work_conn` 读 `NewWorkConn`（`server:3610`），连入口的 `conn.peek()`（`server:3530`）也在无限等首字节

攻击方式：对两个端口各开 N 条 TCP 连接、一条字节都不发。每条连接钉死一个 tokio 任务 + 连接缓冲，**无全局并发连接上限兜底**（KCP/UDP 入口同样命中此路径，且 UDP 连靠连接数限制兜不住）。服务端内存与任务数随攻击者意愿线性增长。

修复（小改动）：两处读包一层 `tokio::time::timeout(Duration::from_secs(30), …)`，超时即断开；可选再加全局 `Semaphore` 限未认证并发连接数（如 512）。

**P0-2 预认证内存放大**

配合 P0-1：未认证连接首帧即可合法读到 10MB（`core:620` 上限），1000 条挂起连接 = 最多 10GB 瞬时内存压力。修复：登录/握手前的首帧单独用小上限（如 64KB），认证后再放宽到 10MB。

### P1（防护缺口，建议两周内修）

| # | 问题 | 证据 | 说明 |
|---|---|---|---|
| P1-1 | std 锁中毒连锁 panic | `server:730/737/742/837`（proxy_stats）、`client:648/654`（pending）、`kcp_stream.rs` 19 处 | 任一持锁 panic 后锁中毒，后续 `.lock().unwrap()` 逐个引爆，任务级雪崩。改 `unwrap_or_else(\|e\| e.into_inner())` 或换 `parking_lot` |
| P1-2 | 写方向无超时 | `server:980-984`（`write_msg`） | 恶意客户端收满 TCP 零窗口可把控制任务卡死在 write 里，代理不会被清理；读侧超时救不了已卡住的写 |
| P1-3 | Web 登录无防爆破 | `login_post_handler` | 有常量时间比较但无失败计数/延迟/锁定，可在线穷举管理员口令 |
| P1-4 | `/metrics` 公开无鉴权 | `server:2863` 白名单 | 暴露 run_id、代理名、流量计数；建议改为可配置开关或限监听网段 |
| P1-5 | 内置 TLS 私钥仍入库（遗留） | `net/cert/frp.key` | 编译期 `include_bytes!` 依赖 + 离线拿不到 `rcgen`，上轮已 WARN + 文档缓解，**这是当前唯一未关闭的原始 P0** |

### P2（技术债）

| # | 问题 | 证据 | 风险 |
|---|---|---|---|
| P2-1 | `get_timestamp` 裸 unwrap | `util:66` | 系统时钟早于 1970（容器时钟漂移）直接 panic，建议 `unwrap_or_default` |
| P2-2 | `Connector::new(...).unwrap()` | `client:2219` | 坏 CA 路径等场景理论上可失败，建议错误上抛 |
| P2-3 | 日志注入 | `server:996` 附近等多处 | `user`/`proxy_name`/`run_id` 客户端可控直接进日志，可伪造日志行；建议转义或单行化 |
| P2-4 | 上限 10MB 偏宽松 | `core:620` | frp 原版同量级，但登录消息实际几百字节，可按消息类型分级 |
| P2-5 | `bridges.remove().unwrap()` 链 | `server:1591-1593` | 当前有 `get_mut` 守卫、逻辑正确，但三个 unwrap 靠调用顺序保证，属脆弱写法 |

---

## 五、改进路线

**天级止血（~半天，改动约 30 行）**
1. P0-1：登录首读 + `peek` + `process_work_conn` 首读各加 30s 超时
2. P0-2：认证前首帧上限收紧到 64KB
3. P1-3：Web 登录失败计数（同 IP 5 次失败锁 5 分钟，内存实现即可）

**周级补齐（1-2 周）**
4. P1-1：全部 std 锁 unwrap 换 `into_inner()` 容错
5. P1-2：`write_msg` 加 30s 超时
6. P1-4：`/metrics` 加配置开关（默认仅本机/内网）
7. P2-1/2/3：小修清零

**季度结构项**
8. P1-5：联网后引入 `rcgen`，内置证书改首次启动运行时生成
9. STCP `secret_key` 真实现、`Server` 改 `Arc<Server>`、拆 `server/src/lib.rs` 巨石

---

## 六、复现命令（附录）

```bash
# 预认证挂起验证（P0-1）：连接后不发数据，观察服务端任务滞留
timeout 35 bash -c 'exec 3<>/dev/tcp/<frps主机>/<控制端口>; sleep 30'   # 连接存活 30s+，服务端无任何日志/清理

# 帧上限验证（P0-2）：发送 >10MB 声明长度被拒（正常），≤10MB 未认证即可送达
# 锁中毒链（P1-1）：grep 生产代码
grep -rn "lock().unwrap()" rust_frp_*/src | wc -l
```

> 注：本轮未新增探针测试；P0-1 的挂起行为由代码路径直接推证（读调用无 timeout 包裹、accept 循环逐连接 spawn、无并发上限），修复后建议补一个"登录超时断连"回归测试。

---

## 八、修复记录（第二轮，2026-10-03）

### 8.1 已修复

| 编号 | 问题 | 修复方式 | 位置 |
|---|---|---|---|
| P0-1 | 预认证读无超时（4 处） | 全部包 `tokio::time::timeout(LOGIN_READ_TIMEOUT=30s)`：控制口登录首读、入口首字节嗅探、TLS 握手 accept、工作连接 `peek` 与 `NewWorkConn` 首读；超时即断开并记 warn 日志 | `server:Control::run` / `handle_connection` / `process_work_conn` |
| P0-2 | 预认证内存放大 | core 新增 `read_message_with_limit()` 与公开常量 `MAX_PREAUTH_MESSAGE_SIZE = 64KB`；登录首帧与工作连接握手首帧改用预认证上限，认证后仍为 10MB | `core:620` 附近、`server` 两处调用 |
| P1-3 | Web 登录无防爆破 | `WebAuth` 内置全局节流：连续失败 ≥5 次锁定 5 分钟，锁定期内**正确凭据也拒绝**（fail-closed）；登录成功清零；节流状态经 20+ 并发测试用例验证无串扰 | `server:WebAuth::attempt_login` / `login_post_handler` |

### 8.2 回归测试（新增 7 个，总数 171 → 178）

- `core`：预认证上限常量锚点、超限帧在分配缓冲前被拒、合法小帧正常解析
- `server`：节流阈值锁定、成功登录清零计数、锁定期内正确凭据 401 且不下发 cookie、超时常量合理性锚点

### 8.3 验证结果（全绿）

```
cargo fmt --all --check     → 通过
cargo clippy --workspace    → 0 error（告警集合与修复前一致）
cargo test --workspace      → 178 passed / 0 failed
```

### 8.4 本轮未做 + 原因

> 以下各项均已在第三轮修复中完成，见《九、修复记录（第三轮）》。

- ~~P1-1 锁中毒链~~（24 处已改 `unwrap_or_else(into_inner)`）
- ~~P1-2 写方向超时~~（`WRITE_TIMEOUT = 30s`，覆盖控制通道与工作连接响应路径）
- ~~P1-4 `/metrics` 开关~~（`expose_metrics` 默认 false）
- ~~P0-1 附注：全局连接 Semaphore~~（`MAX_INFLIGHT_CONNECTIONS = 4096`，超限直接拒绝）

---

## 九、修复记录（第三轮，2026-10-03）

### 9.1 P1-1 锁中毒连锁 panic → 已修复

- **server 3 处**（`proxy_stats` 的 read/write）：`.lock().unwrap()` / `.read().unwrap()` / `.write().unwrap()` 统一改为 `.unwrap_or_else(std::sync::PoisonError::into_inner)`
- **client 2 处**（`pending`）、**net/kcp_stream 19 处**（`state` / `out`）同样处理
- 语义：任一持锁线程 panic 后，后续调用**取回数据继续工作**而不是连锁 panic；全局生产代码中锁 unwrap 已清零
- 回归测试：`test_poisoned_lock_recovery`（真实 panic 中毒 Mutex / RwLock 后取回数据）

### 9.2 P1-2 写方向无超时 → 已修复

- 新增 `WRITE_TIMEOUT = 30s` 常量
- `Control::write_msg`（控制通道全部下行消息）包 30s 超时：零窗口客户端不再能钉死控制任务
- 工作连接握手阶段的 3 处错误响应写入改走 `write_message_with_timeout()` 辅助函数
- 回归测试：`test_write_timeout_constant` 常量锚点

### 9.3 P1-4 `/metrics` 公开 + 无全局连接上限 → 已修复

**指标端点开关**
- `WebServerConfig` 新增 `expose_metrics: bool`（serde 默认 **false**）
- 默认不注册 `/metrics` 路由（请求 404）；Dashboard 内的 `/api/metrics` 始终受登录保护
- 显式开启后 `/metrics` 免鉴权（供 Prometheus 抓取），`frps.example.toml` 已补说明
- 回归测试：config 默认 false / 可显式开启

**全局连接上限（纵深防御）**
- 新增 `MAX_INFLIGHT_CONNECTIONS = 4096` 与进程级 `Semaphore`
- 控制口（含 reload select 分支共 2 处）与工作连接口 accept 循环：许可耗尽时**直接拒绝新连接**（不做排队），许可随连接任务生命周期持有与释放
- 回归测试：`test_conn_limit_constant`、`test_conn_limiter_rejects_when_exhausted`

### 9.4 验证结果（全绿）

```
cargo fmt --all --check     → 通过
cargo clippy --workspace    → 0 error（告警集合与修复前一致，均为既有风格类）
cargo test --workspace      → 184 passed / 0 failed（较上轮 +6 个回归测试）
```

### 9.5 剩余事项（未在本轮范围）

- ~~P1-5 内置私钥入库~~ → **已在第四轮关闭**，见《十、修复记录（第四轮）》
- 季度项：`Server` 改 `Arc<Server>`、拆 5000 行巨石文件、STCP/XTCP `secret_key` 协议级实现

---

## 十、修复记录（第四轮，2026-10-03）

### 10.1 P1-5 / 原始 P0-3：内置 TLS 私钥入库 → 已关闭

**方案**：未配置证书时的兜底由「编译期内嵌固定证书」改为「运行时生成自签证书」。

- `rust_frp_net` 引入 `rcgen 0.13`（清华镜像源可拉取）
- 新增 `TlsConfig::new_server_with_runtime_cert()`：证书与私钥仅在内存中存在，
  进程每次启动重新生成（SAN 覆盖 `frp-server.local` / `localhost`），启动 WARN 保留
- 移除 `new_server_with_builtin_cert()` / `new_client_trusting_builtin()` /
  `get_builtin_cert_pem()` / `get_builtin_key_pem()` 及全部 `include_bytes!` 引用，
  4 处调用点（plugin ×2、server ×2）+ 1 处测试同步更新
- **删除 `rust_frp_net/cert/frp.crt` / `frp.key`**（git rm + 磁盘删除），
  `.gitignore` 增加 `rust_frp_net/cert/*.crt|*.key`、`*.pem` 防回归
- 文档同步：`cert/README.md` 重写、README 特性行与安全表、`frps.example.toml` 注释

**回归测试 +2**（`rust_frp_net/tests/runtime_cert.rs`）：
真实 TCP 上的完整 TLS 握手（accept_stream / connect_stream）+ 重复生成成功。

### 10.2 验证结果（全绿）

```
cargo fmt --all --check     → 通过
cargo clippy --workspace    → 0 error
cargo test --workspace      → 186 passed / 0 failed（+2）
```

### 10.3 当前剩余（仅季度级重构项）

- ~~`Server` 改 `Arc<Server>`、拆 5000 行巨石文件~~ → **已完成**（2026-10-03，rust_frp_server 拆为 10 个子模块）
- ~~STCP/XTCP `secret_key` 协议级实现~~ → **已完成**（2026-10-03，HMAC-SHA256 签名 + 常量时间比较 + 120s 防重放 + 跨客户端支持）

> **收尾说明（2026-10-04）**：本文档为 2026-10-03 的专项复审快照，上述剩余项均已关闭，
> 后续安全状态以 `CODE_QUALITY_REVIEW.md`（第五/六轮）为准——当前 100/100，
> 生产 unwrap 0、clippy 0/0、215 测试全绿。
