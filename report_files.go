package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type savedSession struct {
	Success     bool      `json:"success"`
	GeneratedAt time.Time `json:"generatedAt"`
	Config      config    `json:"config"`
	Result      *report   `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type metricState string

const (
	stateGood    metricState = "good"
	stateWarning metricState = "warning"
	stateBad     metricState = "bad"
	stateInfo    metricState = "info"
)

type metricRow struct {
	Name   string
	Value  string
	Status string
	State  metricState
}

type htmlReportView struct {
	Success         bool
	GeneratedAt     string
	ProxyAddress    string
	Protocol        string
	ExitIP          string
	Assessment      string
	AssessmentState metricState
	RiskScore       string
	Location        string
	Error           string
	Metrics         []metricRow
	Reasons         []string
}

func saveLatestSuccess(directory string, cfg config, result report) (quickReportFiles, error) {
	files, err := quickReportFilesForIP(directory, result.Intel.IP)
	if err != nil {
		return quickReportFiles{}, err
	}
	err = saveLatestSession(directory, savedSession{
		Success:     true,
		GeneratedAt: result.GeneratedAt,
		Config:      cfg,
		Result:      &result,
	}, files)
	return files, err
}

func saveLatestFailure(directory string, cfg config, checkErr error) error {
	return saveLatestSession(directory, savedSession{
		Success:     false,
		GeneratedAt: time.Now().UTC(),
		Config:      cfg,
		Error:       sanitize(checkErr.Error()),
	}, quickReportFiles{
		HTML: filepath.Join(directory, quickErrorHTMLName),
		JSON: filepath.Join(directory, quickErrorJSONName),
	})
}

func saveLatestSession(directory string, session savedSession, files quickReportFiles) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	jsonContent, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	jsonContent = append(jsonContent, '\n')
	htmlContent, err := renderSessionHTML(session)
	if err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	if err := os.WriteFile(files.JSON, jsonContent, 0o600); err != nil {
		return fmt.Errorf("write JSON report: %w", err)
	}
	if err := os.WriteFile(files.HTML, htmlContent, 0o600); err != nil {
		return fmt.Errorf("write HTML report: %w", err)
	}
	return nil
}

func loadLatestSession(path string) (savedSession, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return savedSession{}, err
	}
	var session savedSession
	if err := json.Unmarshal(content, &session); err != nil {
		return savedSession{}, fmt.Errorf("parse saved result: %w", err)
	}
	return session, nil
}

func loadLatestQuickSession(directory string) (savedSession, quickReportFiles, error) {
	_ = migrateLegacyQuickReport(directory)
	candidates, err := reportJSONCandidates(directory, "ipcheck-", "-result.json")
	if err != nil {
		return savedSession{}, quickReportFiles{}, err
	}
	var latest savedSession
	var latestFiles quickReportFiles
	var latestTime time.Time
	var firstErr error
	for _, path := range candidates {
		session, loadErr := loadLatestSession(path)
		if loadErr != nil {
			if firstErr == nil {
				firstErr = loadErr
			}
			continue
		}
		if !session.Success || session.Result == nil {
			continue
		}
		if _, tokenErr := reportIPToken(session.Result.Intel.IP); tokenErr != nil {
			if firstErr == nil {
				firstErr = tokenErr
			}
			continue
		}
		generatedAt := quickSessionTime(session, path)
		if latestFiles.JSON == "" || generatedAt.After(latestTime) {
			latest = session
			latestFiles = quickReportFilesFromJSON(path)
			latestTime = generatedAt
		}
	}
	if latestFiles.JSON != "" {
		return latest, latestFiles, nil
	}
	if firstErr != nil {
		return savedSession{}, quickReportFiles{}, firstErr
	}
	return savedSession{}, quickReportFiles{}, os.ErrNotExist
}

func migrateLegacyQuickReport(directory string) error {
	legacyFiles := quickReportFilesFromJSON(filepath.Join(directory, "ipcheck-last-result.json"))
	legacySession, err := loadLatestSession(legacyFiles.JSON)
	if err != nil || !legacySession.Success || legacySession.Result == nil {
		return err
	}
	targetFiles, err := quickReportFilesForIP(directory, legacySession.Result.Intel.IP)
	if err != nil {
		return err
	}
	if targetSession, targetErr := loadLatestSession(targetFiles.JSON); targetErr == nil && targetSession.Success && targetSession.Result != nil {
		if !quickSessionTime(legacySession, legacyFiles.JSON).After(quickSessionTime(targetSession, targetFiles.JSON)) {
			return removeReportFiles(legacyFiles.HTML, legacyFiles.JSON)
		}
	}
	return migrateReportFiles([]reportFilePair{
		{source: legacyFiles.HTML, target: targetFiles.HTML},
		{source: legacyFiles.JSON, target: targetFiles.JSON},
	})
}

func quickSessionTime(session savedSession, jsonPath string) time.Time {
	generatedAt := session.GeneratedAt
	if generatedAt.IsZero() && session.Result != nil {
		generatedAt = session.Result.GeneratedAt
	}
	if generatedAt.IsZero() {
		if info, err := os.Stat(jsonPath); err == nil {
			generatedAt = info.ModTime()
		}
	}
	return generatedAt
}

func saveConfig(path string, cfg config) error {
	content, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

func renderSessionHTML(session savedSession) ([]byte, error) {
	configuredProtocol := configConnectionProtocol(session.Config)
	view := htmlReportView{
		Success:      session.Success,
		GeneratedAt:  session.GeneratedAt.Local().Format("2006-01-02 15:04:05"),
		ProxyAddress: connectionAddress(session.Config.ProxyHost, session.Config.ProxyPort, configuredProtocol),
		Protocol:     protocolDisplayName(configuredProtocol),
		Error:        session.Error,
	}
	if session.Result != nil {
		result := *session.Result
		view.ProxyAddress = connectionAddress(result.ProxyHost, result.ProxyPort, result.ProxyProtocol)
		view.Protocol = protocolDisplayName(result.ProxyProtocol)
		view.ExitIP = result.Intel.IP
		view.Assessment, view.AssessmentState = assessmentLabel(result.Assessment)
		view.RiskScore = fmt.Sprintf("%.0f / 100", riskPercent(result.Intel.Security.Score))
		view.Location = formatLocation(result.Intel.Location)
		view.Metrics = metricsForReport(result)
		view.Reasons = translatedReasons(result.AssessmentReasons)
	}

	var output bytes.Buffer
	if err := reportTemplate.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func connectionAddress(host string, port int, protocol string) string {
	if normalizeProtocol(protocol) == protocolDirect {
		return "未使用代理"
	}
	return netJoinHostPort(host, port)
}

func metricsForReport(value report) []metricRow {
	risk := riskPercent(value.Intel.Security.Score)
	riskState, riskStatus := stateGood, "正常"
	if risk >= 70 {
		riskState, riskStatus = stateBad, "高风险"
	} else if risk >= 30 {
		riskState, riskStatus = stateWarning, "需复核"
	}
	latencyState, latencyStatus := stateInfo, "信息"
	if value.LatencyMS >= 5000 {
		latencyState, latencyStatus = stateWarning, "较慢"
	}

	rows := []metricRow{
		{Name: "出口 IP", Value: sanitize(value.Intel.IP) + " (" + sanitize(value.Intel.Version) + ")", Status: "已获取", State: stateGood},
		{Name: "连接方式", Value: protocolDisplayName(value.ProxyProtocol), Status: "已验证", State: stateGood},
		{Name: "查询延迟", Value: fmt.Sprintf("%d ms", value.LatencyMS), Status: latencyStatus, State: latencyState},
		{Name: "地区", Value: formatLocation(value.Intel.Location), Status: "信息", State: stateInfo},
		{Name: "时区", Value: sanitize(value.Intel.Location.Timezone), Status: "信息", State: stateInfo},
		{Name: "ASN", Value: sanitize(value.Intel.Network.ASN), Status: "信息", State: stateInfo},
		{Name: "ISP", Value: sanitize(value.Intel.Network.ISP), Status: "信息", State: stateInfo},
		{Name: "组织", Value: sanitize(value.Intel.Network.Organization), Status: "信息", State: stateInfo},
		{Name: "线路类型", Value: sanitize(value.Intel.Network.ConnectionType), Status: "信息", State: stateInfo},
		{Name: "风险分数", Value: fmt.Sprintf("%.0f / 100", risk), Status: riskStatus, State: riskState},
		booleanRiskMetric("VPN 标记", value.Intel.Security.IsVPN, false),
		booleanRiskMetric("代理数据库标记", value.Intel.Security.IsProxy, false),
		booleanRiskMetric("Tor 出口", value.Intel.Security.IsTor, true),
		booleanRiskMetric("Hosting / 机房", value.Intel.Security.IsHosting, false),
		booleanRiskMetric("黑名单", value.Intel.Security.IsBlacklisted, true),
		checkMetric("独立信誉", value.Blackbox, "allow", "建议放行", "建议拦截"),
		availabilityMetric("ChatGPT", value.ChatGPT, "可访问，区域 "),
		availabilityMetric("Google", value.Google, "可访问"),
	}
	return rows
}

func booleanRiskMetric(name string, detected, severe bool) metricRow {
	if !detected {
		return metricRow{Name: name, Value: "未发现", Status: "正常", State: stateGood}
	}
	if severe {
		return metricRow{Name: name, Value: "已发现", Status: "高风险", State: stateBad}
	}
	return metricRow{Name: name, Value: "已发现", Status: "需复核", State: stateWarning}
}

func checkMetric(name string, value checkResult, goodValue, goodText, warningText string) metricRow {
	if !value.Available {
		return metricRow{Name: name, Value: "未返回：" + sanitize(value.Error), Status: "不可用", State: stateWarning}
	}
	if value.Value == goodValue {
		return metricRow{Name: name, Value: goodText, Status: "正常", State: stateGood}
	}
	return metricRow{Name: name, Value: warningText, Status: "需复核", State: stateWarning}
}

func availabilityMetric(name string, value checkResult, availablePrefix string) metricRow {
	if !value.Available {
		return metricRow{Name: name, Value: "不可访问：" + sanitize(value.Error), Status: "不可用", State: stateWarning}
	}
	display := availablePrefix
	if value.Value != "" && value.Value != "reachable" {
		display += sanitize(value.Value)
	}
	return metricRow{Name: name, Value: display, Status: "正常", State: stateGood}
}

func assessmentLabel(value string) (string, metricState) {
	switch {
	case strings.HasPrefix(value, "high"):
		return "高风险", stateBad
	case strings.HasPrefix(value, "review"):
		return "建议复核", stateWarning
	default:
		return "低风险", stateGood
	}
}

func translatedReasons(reasons []string) []string {
	translated := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		switch {
		case reason == "primary source reports blacklist membership":
			translated = append(translated, "主数据源报告该 IP 位于黑名单中")
		case reason == "Tor exit detected":
			translated = append(translated, "检测到 Tor 出口")
		case reason == "VPN or proxy signal detected":
			translated = append(translated, "检测到 VPN 或代理数据库信号")
		case reason == "hosting/datacenter signal detected":
			translated = append(translated, "检测到机房或托管网络信号")
		case reason == "independent source recommends blocking":
			translated = append(translated, "独立信誉数据源建议拦截")
		case strings.HasPrefix(reason, "risk score is "):
			translated = append(translated, "风险分数为 "+strings.TrimPrefix(reason, "risk score is "))
		case reason == "no major risk signal was returned":
			translated = append(translated, "当前数据源未返回主要风险信号")
		default:
			translated = append(translated, sanitize(reason))
		}
	}
	return translated
}

func formatLocation(value locationData) string {
	parts := make([]string, 0, 4)
	for _, item := range []string{value.City, value.Region, value.Country} {
		item = strings.TrimSpace(sanitize(item))
		if item != "" {
			parts = append(parts, item)
		}
	}
	location := strings.Join(parts, ", ")
	if countryCode := sanitize(value.CountryCode); countryCode != "" {
		location += " (" + countryCode + ")"
	}
	if location == "" {
		return "未知"
	}
	return location
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Proxy IP 检测结果</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#66717c;--line:#dce2e8;--panel:#fff;--canvas:#f3f5f7;--good:#137a5a;--good-bg:#eaf6f1;--warn:#9a6300;--warn-bg:#fff5dc;--bad:#b42318;--bad-bg:#ffebe9;--info:#285f9e;--info-bg:#edf4fb}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.55 "Microsoft YaHei UI","Segoe UI",sans-serif;letter-spacing:0}
.shell{max-width:1040px;margin:0 auto;padding:28px 22px 44px}.top{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:18px}
.brand{font-size:22px;font-weight:700}.eyebrow{font-size:12px;color:var(--info);font-weight:700;margin-bottom:2px}.meta{color:var(--muted);text-align:right}
.summary{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:10px;margin-bottom:14px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;min-width:0}
.stat-label{font-size:12px;color:var(--muted);margin-bottom:5px}.stat-value{font-size:19px;font-weight:700;overflow-wrap:anywhere}.stat-sub{font-size:12px;color:var(--muted);margin-top:4px}
.state-good{color:var(--good)}.state-warning{color:var(--warn)}.state-bad{color:var(--bad)}.state-info{color:var(--info)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}.panel-head{padding:13px 16px;border-bottom:1px solid var(--line);font-weight:700}
table{width:100%;border-collapse:collapse}th,td{padding:10px 16px;text-align:left;border-bottom:1px solid #edf0f3;vertical-align:top}th{font-size:12px;color:var(--muted);background:#fafbfc;font-weight:600}tr:last-child td{border-bottom:0}
.metric{width:24%;font-weight:600}.value{overflow-wrap:anywhere}.status{width:100px;font-weight:700}.reasons{margin:14px 0 0;padding:13px 18px 13px 36px;background:var(--warn-bg);border:1px solid #eed596;border-radius:6px;color:#6f4a00}
.failure{background:var(--bad-bg);border:1px solid #f2b8b5;border-radius:6px;padding:18px;color:#7a271a}.failure h2{font-size:18px;margin:0 0 8px}.failure p{margin:0;overflow-wrap:anywhere}
.foot{display:flex;justify-content:space-between;gap:20px;color:var(--muted);font-size:12px;margin-top:14px}@media(max-width:720px){.summary{grid-template-columns:1fr}.top,.foot{align-items:flex-start;flex-direction:column}.meta{text-align:left}.metric{width:32%}th,td{padding:9px 10px}.status{width:72px}}
</style>
</head>
<body><main class="shell">
<header class="top"><div><div class="eyebrow">LOCAL IP REPORT</div><div class="brand">Proxy IP 质量检测</div></div><div class="meta">{{.GeneratedAt}}<br>{{.ProxyAddress}} · {{.Protocol}}</div></header>
{{if .Success}}
<section class="summary">
<div class="stat"><div class="stat-label">出口 IP</div><div class="stat-value">{{.ExitIP}}</div><div class="stat-sub">{{.Location}}</div></div>
<div class="stat"><div class="stat-label">综合判断</div><div class="stat-value state-{{.AssessmentState}}">{{.Assessment}}</div><div class="stat-sub">多数据源综合信号</div></div>
<div class="stat"><div class="stat-label">风险分数</div><div class="stat-value">{{.RiskScore}}</div><div class="stat-sub">分数越高风险越大</div></div>
</section>
<section class="panel"><div class="panel-head">检测指标</div><table><thead><tr><th>指标</th><th>检测结果</th><th>状态</th></tr></thead><tbody>
{{range .Metrics}}<tr><td class="metric">{{.Name}}</td><td class="value">{{.Value}}</td><td class="status state-{{.State}}">{{.Status}}</td></tr>{{end}}
</tbody></table></section>
{{if .Reasons}}<ul class="reasons">{{range .Reasons}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{else}}
<section class="failure"><h2>检测未完成</h2><p>{{.Error}}</p></section>
{{end}}
<footer class="foot"><span>结果来自公开数据源，仅作为公网出口 IP 质量判断信号。</span><span>Proxy IP Quality Checker</span></footer>
</main></body></html>`))
