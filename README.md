# Proxy IP Quality Checker

一个免安装的 Windows 公网出口 IP 检测工具，可检测本地代理出口，也可绕过代理直接检测当前电脑的公网 IP。

解压后双击 `ipcheck.exe` 即可。使用端不需要安装 Docker、WSL、Git、Go、Python、Node.js 或其他运行库，也不需要管理员权限。

## 两种检测模式

| 模式 | 用途 | 检测时间 | 输出 |
| --- | --- | --- | --- |
| 快速检测 | 日常确认代理或本机直连出口地址及主要风险信号 | 通常数秒 | 18 项指标 |
| IPQuality 完整检测 | 运行固定版本的 [xykt/IPQuality](https://github.com/xykt/IPQuality) 全部检测模块 | 通常数分钟，本机首次实测约 6 分钟 | 30 项以上解析指标和完整原始报告 |

完整模式不是重新仿写一组相似指标，而是直接运行随程序附带、可查看源码的 IPQuality 脚本。当前固定上游提交为 `44c35cca002782ddd6364e039be2949a2535d1cc`，脚本版本为 `v2026-03-29`。

## 界面功能

- 地址输入，默认 `127.0.0.1`
- 端口输入，默认 `7897`
- `7897`、`7890`、`1080` 常用端口按钮
- 自动识别、HTTP / Mixed、SOCKS5 协议选择
- “本机直连（不使用代理）”开关；启用后自动停用代理地址、端口和协议控件
- 快速检测、IPQuality 完整检测模式选择，默认使用完整检测
- 后台运行、进度显示和取消
- 指标概览与 IPQuality 原始报告标签页
- 一键复制摘要、打开 HTML 报告、打开报告目录
- 启动时恢复两种模式各自最近一次成功结果

取消不会覆盖上一次成功报告。完整模式会终止内置 Bash 及其子进程，不会在后台继续检测。

## 完整检测内容

IPQuality 完整模式保留原项目的六个部分：

1. MaxMind 基础信息、ASN、组织、地区和时区
2. 多数据库 IP 使用类型与公司类型
3. IP2Location、Scamalytics、ipapi、AbuseIPDB、IPQS、DB-IP 风险分数
4. 国家代码、Proxy、Tor、VPN、Server、Abuser、Robot 风险因子
5. TikTok、Disney+、Netflix、YouTube、Amazon Prime Video、Reddit、ChatGPT 解锁情况
6. 邮件服务连通性和 DNSBL 黑名单检测

上游 JSON 偶尔会遗漏正文中已经显示的字段，例如正文有 IPQS 分数而 JSON 为 `null`。程序不会修改保存的原始 JSON，只会从原始文本补齐界面和 HTML 中的解析值。

## 使用方法

1. 从 [Releases](../../releases) 下载 `ProxyIPCheck-windows-amd64.zip` 并解压。
2. 双击 `ipcheck.exe`。
3. 检测代理时启动代理软件并确认地址、端口；不了解协议时选择“自动识别”。
4. 检测本机公网 IP 时勾选“本机直连（不使用代理）”。
5. 选择“快速检测”或“IPQuality 完整检测”，然后点击“开始检测”。

完整检测期间可正常使用电脑；代理模式下不要关闭本地代理。部分公开数据库响应较慢，进度停留一段时间不代表程序卡死。

## 本地报告

快速检测完成后生成（以出口 `203.0.113.10` 为例）：

- `ipcheck-203.0.113.10-result.html`
- `ipcheck-203.0.113.10-result.json`

IPQuality 完整检测完成后生成：

- `ipquality-203.0.113.10-result.html`：解析指标和原始文本合并报告
- `ipquality-203.0.113.10-original.html`：保留上游深色背景、ANSI 字体颜色和等宽排版的原始报告
- `ipquality-203.0.113.10-result.json`：原项目生成的原始 JSON，不增加包装字段
- `ipquality-203.0.113.10-result.txt`：去除终端颜色后的原始文本报告
- `ipquality-203.0.113.10-result.meta.json`：本工具保存的协议和生成时间等元数据

所有文件都保存在 `ipcheck.exe` 同一目录。不同出口 IP 的报告分别保留；同一出口 IP 再次检测时只更新该 IP 对应的文件。程序启动时会扫描这些文件并恢复时间最新的结果；旧版本的 `*-last-result.*` 报告会在确认内容有效后自动迁移为带出口 IP 的文件名，如果同一 IP 已有新报告则只保留时间更新的那组。检测失败时另存错误文件，不会删除之前成功的报告。

## 配置文件

```json
{
  "proxyHost": "127.0.0.1",
  "proxyPort": 7897,
  "proxyProtocol": "auto",
  "directConnection": false,
  "checkMode": "ipquality",
  "timeoutSeconds": 20,
  "pauseOnExit": false
}
```

`directConnection` 为 `true` 时完全绕过代理，地址、端口和协议仅保留配置但不参与检测。`proxyProtocol` 支持 `auto`、`http`、`socks5`；`checkMode` 支持 `quick`、`ipquality`。新配置以及没有 `checkMode` 的旧配置默认使用完整检测；已经明确保存过模式的配置继续尊重原选择。

## 依赖与打包

客户端只需要 Windows 10/11 x64 和可访问检测服务的网络。只有检测代理出口时，才需要一个已经运行的本地 HTTP/Mixed/SOCKS5 代理。

发布目录已经包含精简的 Git Bash/MSYS2 运行时、curl、jq 和本项目的原生兼容助手。Docker 只可作为开发构建环境，不属于客户端，也不会在其他电脑上安装任何组件。当前本地免安装 ZIP 约 17 MB，解压约 37 MB。

## 数据与隐私

快速模式会通过所选连接方式访问 whatismyip.ai、ipinfo.app、ChatGPT trace 和 Google connectivity check。

完整模式会按 IPQuality 原项目逻辑访问多个公开 IP 情报、流媒体、AI 和邮件检测服务。这些服务能够看到被检测的公网出口 IP；选择本机直连时，它们看到的是当前电脑真实的公网出口 IP。DNSBL 域名查询使用电脑当前 DNS 解析器查询该出口 IP 的名单状态。

嵌入模式做了以下隐私调整：

- 启用上游 `-p` 隐私参数，不上传在线报告
- 跳过原项目广告
- 跳过非检测用途的运行次数统计请求
- 在获取公网 IP 前先解析代理参数
- 参考数据下载也使用所选连接方式
- 本机直连模式会清除继承的代理环境变量，并且不向 IPQuality 传入代理参数

程序不会执行网络上临时下载的脚本，不会上传本机文件、配置文件或本地报告。不同数据库可能互相矛盾，综合判断只用于筛查，不是绝对结论。

## 从源码构建

应用使用 Go 1.25.12 构建。生成 GUI 和兼容助手后，可用本机 Git for Windows 组装精简运行时：

```powershell
go test ./...
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -tags gui -trimpath -ldflags "-s -w -H windowsgui" -o dist\ipcheck-preview.exe .
go build -trimpath -ldflags "-s -w" -o dist\ipquality-helper.exe .\cmd\ipquality-helper
.\tools\build_portable_preview.ps1 -GitRoot "C:\Program Files\Git"
```

`tools/prepare_ipquality_runtime.ps1` 会固定校验 jq 1.8.1 的 SHA-256，并只复制 IPQuality 实际需要的 Bash 命令和 DLL。`rsrc_windows_amd64.syso` 包含图标、Common Controls 和 DPI 清单。

## 许可证

本项目的 Go 应用代码采用 [MIT](LICENSE) 许可证。随包提供的 IPQuality 修改源码采用 AGPL-3.0；jq、Git Bash/MSYS2、curl 及其库分别采用各自许可证，详见 `THIRD_PARTY_NOTICES.txt`、`ipquality` 和 `runtime/licenses`。
