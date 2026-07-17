# Proxy IP Quality Checker

一个真正免安装的 Windows 代理出口 IP 质量检测工具。Release 中的 `ipcheck.exe` 是静态编译的原生程序，解压后直接双击即可，不需要 Docker、WSL、Python、Node.js、PowerShell 或管理员权限。

## 检测项目

- 代理出口 IPv4/IPv6
- 查询延迟
- 国家、地区、城市和时区
- ASN、ISP 和组织
- 住宅/机房等线路类型
- 风险分数
- VPN 标记
- 代理数据库标记
- Tor 出口标记
- Hosting/机房标记
- 黑名单标记
- 第二数据源的独立放行/拦截建议
- ChatGPT 连通性及地区
- Google 连通性
- 基于以上信号的本地综合判断

## 使用方法

1. 从 [Releases](../../releases) 下载 `ProxyIPCheck-windows-amd64.zip`。
2. 解压 ZIP。
3. 启动本地代理软件。
4. 双击 `ipcheck.exe`。

默认检测 `127.0.0.1:7897`。如果端口不同，修改同目录下的 `config.json`：

```json
{
  "proxyHost": "127.0.0.1",
  "proxyPort": 7897,
  "timeoutSeconds": 20,
  "saveJson": false,
  "pauseOnExit": true
}
```

当前版本支持 HTTP 代理和 Clash/Mihomo 等软件的混合端口。SOCKS-only 端口暂不支持；请在代理软件中开启 HTTP 或 mixed-port。

即使删除 `config.json`，程序也会使用 `127.0.0.1:7897` 作为默认配置，因此 `ipcheck.exe` 可以单文件运行。

## 运行依赖

客户端只需要：

- Windows 10/11 x64
- 已经运行的本地 HTTP/混合代理
- 可访问检测服务的网络

无需安装任何运行库。Docker 只用于开发者在本地构建和测试，不属于客户端依赖。

## 数据来源与隐私

主要 IP 情报来自 [whatismyip.ai API](https://whatismyip.ai/api)，该接口公开说明无需 API Key，并返回地理位置、ASN、线路类型和安全信号。独立信誉结论来自 [ipinfo.app Blackbox v1](https://ipinfo.app/api/blackbox/)，官方说明 v1 免费且无需认证。

程序还会通过待检测代理访问 ChatGPT Cloudflare trace 和 Google connectivity check。检测服务能够看到代理出口 IP，这是完成检测所必需的。程序不会上传代理地址、配置文件或本机文件，也不支持在配置中保存代理用户名和密码。

不同数据库可能得出不同结果。程序会并列显示信号，不把任何单一结果当作绝对结论。

## 从源码构建

```powershell
go test ./...
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w" -o dist\ipcheck.exe .
```

源码最低兼容 Go 1.22；官方 Release 使用 Go 1.26.5 构建。Release 用户不需要安装 Go。

Windows 可能因为程序尚未购买代码签名证书而显示 SmartScreen 提示。请从本仓库 Release 下载，并使用同页的 `SHA256SUMS.txt` 校验 ZIP；对未签名程序有顾虑时，可以按上面的命令自行从源码构建。

## 许可证

[MIT](LICENSE)
