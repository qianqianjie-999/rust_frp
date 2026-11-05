# rust_frp Windows 客户端部署指南（visitor 访客端）

适用场景：让一台 Windows 机器通过 STCP 访客隧道访问内网服务（如播报机 SSH、
配置台 Web），本机只做 visitor，**不占公网端口、不需要 frps 侧安全组放行**。

> 实战参考：local_win(192.168.31.5) → 播报机 debian13，
> `127.0.0.1:9311 → 播报机 sshd`、`127.0.0.1:8080 → 播报机配置台`。

## 一、包文件清单

| 文件 | 作用 |
|---|---|
| `rust_frpc.exe` | 客户端主程序（Windows x64，交叉编译产物） |
| `frpc.toml` | 客户端配置（含 token/secret_key，**禁止外传**） |
| `ca.crt` | frps 内部 CA 证书 |
| `client-XX.crt/.key` | 本客户端 mTLS 证书（每台机器唯一 CN） |
| `install.bat` | 一键安装（管理员）：拷文件→离线校验→注册计划任务→启动 |
| `run.cmd` | 看门狗启动器：frpc 退出后 10 秒自动拉起 |
| `uninstall.bat` | 卸载（只删计划任务，保留文件） |
| `update.bat` | 升级：停任务→备份→换 exe→重启 |

脱敏模板见 [`frpc.windows.example.toml`](../deploy/windows/frpc.windows.example.toml)。

## 二、构建 rust_frpc.exe（Linux 构建机上交叉编译）

在构建机（如 C32）上执行：

```bash
# 一次性环境准备
sudo dnf install -y mingw64-gcc          # Rocky 9 需启用 CRB 仓库
rustup target add x86_64-pc-windows-gnu

# 编译（仓库根目录）
./deploy/windows/build-windows.sh dist
```

产物 `dist/rust_frpc.exe` 传回 Windows 后先核对哈希：

```bat
certutil -hashfile rust_frpc.exe SHA256
```

## 三、安装方法

1. 把整个包目录拷到 Windows 机器（任意位置，建议路径不带空格）
2. 按实际情况改好 `frpc.toml`（client_id、证书文件名、server_name），
   并在 `install.bat` 顶部「customize here」区块核对证书文件名与任务名
3. 右键 `install.bat` → **以管理员身份运行**（不是管理员它会自动弹 UAC）
4. 脚本做 5 件事：
   - 建 `C:\frpc` 并拷贝全部文件
   - `rust_frpc.exe verify -c` 离线校验配置（证书路径写错这里就会报）
   - 注册计划任务 `rust_frpc_win`（SYSTEM 身份 / 开机自启 / HIGHEST）
   - 立即启动并打印监听端口与日志尾部
5. 看到 `127.0.0.1:9311 / 8080 ... LISTENING` 即成功

## 四、启动 / 停止 / 重启命令

计划任务名默认 `rust_frpc_win`（管理员 cmd）：

```bat
schtasks /Run  /TN rust_frpc_win      :: 启动
schtasks /End  /TN rust_frpc_win      :: 停止(看门狗会退出)
schtasks /Run  /TN rust_frpc_win      :: (停止后再执行即重启)

schtasks /Query /TN rust_frpc_win /V  :: 查看任务状态
tasklist | findstr /i rust_frpc       :: 看进程在不在
```

注意：直接 `taskkill` 进程没用 —— run.cmd 看门狗会在 10 秒后把它拉起来；
要真停就先 `schtasks /End` 再杀进程。

## 五、开机自启机制

- 计划任务：`schtasks /Create /TN rust_frpc_win /TR C:\frpc\run.cmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F`
  - SYSTEM 身份、开机（ONSTART）触发、最高权限
- 看门狗：任务实际启动的是 `run.cmd`，它是一个死循环 —— frpc 退出就写一行日志、
  等 10 秒重新拉起。所以崩溃自愈、更新 exe 也只是"闪断 10 秒"
- 日志：`C:\frpc\frpc.log`（追加式，过大时停任务→改名→再启动）

## 六、升级

```bat
:: 新 exe 和 update.bat 放同一目录，右键管理员运行
update.bat
:: 它会: 停任务 → 备份旧 exe 为 rust_frpc.exe.bak → 换新 → 重启 → 打印版本
```

回滚：把 `C:\frpc\rust_frpc.exe.bak` 复制回去重启任务即可。

## 七、验证

```bat
curl --noproxy "*" http://127.0.0.1:8080/    :: 配置台(401=通)
curl --noproxy "*" http://127.0.0.1:9310/    :: frpc 管理页(看 visitor 状态)
ssh -p 9311 user@127.0.0.1                   :: SSH 隧道
```

## 八、常见坑

1. **协议版本必须与服务端匹配**：新版 frps 要求 STCP 客户端带 `bridge_id`，
   2026-10-27 之前编译的旧版会被 frps 拒绝（`bridge_id is required`）。
   升级服务端时把所有客户端一起升。
2. **证书必须绝对路径**：计划任务以 SYSTEM 启动时工作目录是 System32，
   `frpc.toml` 里相对路径必挂。
3. **`server_name` 必须与被访问端 `[[proxies]]` name 一字不差**，写错 frps 回
   `proxy not found`。
4. **本机系统代理劫持 127.0.0.1**：curl 加 `--noproxy "*"`，浏览器把 127.0.0.1
   加入"不使用代理"列表。
5. **`frpc.toml` 含 token/secret_key 明文**，机器之间拷贝没问题，不要提交到仓库。
