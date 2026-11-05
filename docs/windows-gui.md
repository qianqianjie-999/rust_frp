# rust_frp Windows 图形界面版（GUI）安装指南

图形界面版包含**成对**的两个程序，与命令行版（rust_frpc / rust_frps）功能一致：

| 程序 | 说明 | 内嵌核心 |
|---|---|---|
| `rust_frps-gui.exe` | **服务端** GUI：托盘 + 配置窗口，进程内运行服务端 | rust_frp_server |
| `rust_frpc-gui.exe` | **客户端** GUI：托盘 + 配置窗口，进程内运行客户端 | rust_frp_client |

对应命令行版用户请看 `deploy/INSTALL-linux-frps.md` / `INSTALL-linux-frpc.md` / `docs/windows-client.md`。

## 1. 环境要求

- Windows 7 ~ Windows 11 x64
- **WebView2 运行时**：Win11 自带；Win7/10 若首次启动报 WebView2 错误，
  安装微软 [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)（Evergreen Bootstrapper）
- 如包内附有 `WebView2Loader.dll`，与 exe 放同一目录

## 2. 安装方法（绿色免安装）

1. 新建目录，如 `C:\rust_frp\`
2. 把 `rust_frps-gui.exe`（服务端机）或 `rust_frpc-gui.exe`（客户端机）放进去
3. 双击运行即可 —— **首次启动自动生成默认配置**（exe 同级）：
   - 服务端：`frps-win.toml`，日志 `frps-gui.log`
   - 客户端：`frpc-win.toml`，日志 `frpc-gui.log`
4. 在窗口里填好参数（服务端：控制端口 + Token；客户端：服务器地址/端口 + Token），
   点「保存配置」→「启动」

> 升级：退出托盘 → 覆盖 exe → 重新启动。配置文件与日志不受影响。

## 3. 开机自启

三种方式任选：

- **界面（推荐）**：窗口「开机自启」勾选，或托盘右键菜单点「开机自启」
  （写入 `HKCU\...\CurrentVersion\Run`，无需管理员权限）
- **计划任务**（服务端机建议，登录前即生效）：

  ```bat
  schtasks /Create /TN rust_frps_gui /SC ONSTART /RU SYSTEM ^
    /TR "\"C:\rust_frp\rust_frps-gui.exe\"" /RL HIGHEST /F
  schtasks /Run /TN rust_frps_gui
  ```

- **启动文件夹**：`Win+R` → `shell:startup` → 放 exe 快捷方式

注意：SYSTEM 计划任务方式与 HKCU 自启**不要同时开**（程序内置单实例保护，
第二实例会自动退出，但建议只留一种）。

## 4. 常用操作

| 操作 | 入口 |
|---|---|
| 启动 / 停止 / 重载配置 | 窗口按钮 或 托盘右键菜单 |
| 最小化到托盘 | 点窗口 ✕（隐藏不退出，托盘图标仍在） |
| 真正退出 | 托盘右键 → 退出 |
| 看日志 | exe 同级 `frps-gui.log` / `frpc-gui.log`（按天保留 7 天） |

- 服务端托盘图标：绿=运行中，琥珀=启动中，灰=已停止/错误
- 服务端配置热重载：窗口「保存配置」或直接改 `frps-win.toml`，运行中自动生效
- 客户端状态轮询走管理端口（默认 127.0.0.1:9310）；服务端走 Dashboard `/healthz`

## 5. 常见问题

- **双击没反应 / 闪退**：看同目录日志；最常见是缺 WebView2 运行时（见第 1 节）
- **端口被占**：服务端「初始化失败（监听端口被占用？）」→ 换端口或停掉占用者
  （`netstat -ano | findstr :9300`）
- **STCP 连不上**：两端 Token / server_name / secret_key 必须一致；
  frps 与所有 frpc **同步升级**（新版协议要求 STCP 带 bridge_id）
