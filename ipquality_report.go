package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ipqualityErrorName        = "ipquality-last-error.txt"
	ipqualityOriginalHTMLName = "ipquality-last-original.html"
)

type ipqualityHTMLView struct {
	GeneratedAt     string
	ProxyAddress    string
	Protocol        string
	ExitIP          string
	Location        string
	Assessment      string
	AssessmentState metricState
	RiskScore       string
	SourceVersion   string
	SourceURL       string
	Metrics         []metricRow
	Reasons         []string
	TerminalHTML    template.HTML
}

func saveLatestIPQuality(directory string, result ipqualityResult) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("创建报告目录失败: %w", err)
	}
	if _, err := parseIPQualityDocument(result.RawJSON); err != nil {
		return fmt.Errorf("拒绝保存无效的原始结果: %w", err)
	}
	metadata := ipqualityMetadata{
		GeneratedAt:       result.GeneratedAt,
		ProxyHost:         result.ProxyHost,
		ProxyPort:         result.ProxyPort,
		ProxyProtocol:     result.ProxyProtocol,
		Assessment:        result.Assessment,
		AssessmentReasons: result.AssessmentReasons,
	}
	metaJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("编码完整检测元数据失败: %w", err)
	}
	htmlContent, err := renderIPQualityHTML(result)
	if err != nil {
		return fmt.Errorf("生成完整检测 HTML 失败: %w", err)
	}
	originalHTML := renderTerminalDocument(ipqualityTerminalSource(result))
	rawJSON := append(bytes.TrimSpace(result.RawJSON), '\n')
	plainText := []byte(strings.TrimSpace(result.PlainText) + "\r\n")
	files := []struct {
		name    string
		content []byte
	}{
		{ipqualityJSONName, rawJSON},
		{ipqualityTextName, plainText},
		{ipqualityMetaName, append(metaJSON, '\n')},
		{ipqualityHTMLName, htmlContent},
		{ipqualityOriginalHTMLName, originalHTML},
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(directory, file.name), file.content, 0o600); err != nil {
			return fmt.Errorf("保存 %s 失败: %w", file.name, err)
		}
	}
	_ = os.Remove(filepath.Join(directory, ipqualityErrorName))
	return nil
}

func saveIPQualityFailure(directory string, checkErr error) error {
	content := time.Now().Format("2006-01-02 15:04:05") + "\r\n" + sanitize(checkErr.Error()) + "\r\n"
	return os.WriteFile(filepath.Join(directory, ipqualityErrorName), []byte(content), 0o600)
}

func loadLatestIPQuality(directory string, fallback config) (ipqualityResult, error) {
	rawJSON, err := os.ReadFile(filepath.Join(directory, ipqualityJSONName))
	if err != nil {
		return ipqualityResult{}, err
	}
	document, err := parseIPQualityDocument(rawJSON)
	if err != nil {
		return ipqualityResult{}, err
	}
	result := ipqualityResult{
		GeneratedAt:   time.Now().UTC(),
		ProxyHost:     fallback.ProxyHost,
		ProxyPort:     fallback.ProxyPort,
		ProxyProtocol: configConnectionProtocol(fallback),
		Document:      document,
		RawJSON:       rawJSON,
	}
	if info, statErr := os.Stat(filepath.Join(directory, ipqualityJSONName)); statErr == nil {
		result.GeneratedAt = info.ModTime().UTC()
	}
	if content, readErr := os.ReadFile(filepath.Join(directory, ipqualityTextName)); readErr == nil {
		result.PlainText = cleanIPQualityText(string(content))
	}
	if result.PlainText == "" {
		result.PlainText = buildIPQualityPlainText(document)
	}
	enrichIPQualityDocumentFromText(&result.Document, result.PlainText)
	if content, readErr := os.ReadFile(filepath.Join(directory, ipqualityMetaName)); readErr == nil {
		var metadata ipqualityMetadata
		if json.Unmarshal(content, &metadata) == nil {
			if !metadata.GeneratedAt.IsZero() {
				result.GeneratedAt = metadata.GeneratedAt
			}
			if metadata.ProxyHost != "" {
				result.ProxyHost = metadata.ProxyHost
			}
			if metadata.ProxyPort > 0 {
				result.ProxyPort = metadata.ProxyPort
			}
			if protocol := normalizeProtocol(metadata.ProxyProtocol); protocol != protocolAuto {
				result.ProxyProtocol = protocol
			}
			result.Assessment = metadata.Assessment
			result.AssessmentReasons = metadata.AssessmentReasons
		}
	}
	result.Assessment, result.AssessmentReasons = assessIPQuality(result.Document)
	return result, nil
}

func renderIPQualityHTML(result ipqualityResult) ([]byte, error) {
	assessment, state := assessmentLabel(result.Assessment)
	riskText := "未返回有效分数"
	if score, source, ok := maxIPQualityScore(result.Document.Score); ok {
		riskText = fmt.Sprintf("%.0f / 100 · %s", score, source)
	}
	view := ipqualityHTMLView{
		GeneratedAt:     result.GeneratedAt.Local().Format("2006-01-02 15:04:05"),
		ProxyAddress:    connectionAddress(result.ProxyHost, result.ProxyPort, result.ProxyProtocol),
		Protocol:        protocolDisplayName(result.ProxyProtocol),
		ExitIP:          ipqualityValue(result.Document.Head.IP),
		Location:        ipqualityLocation(result.Document.Info),
		Assessment:      assessment,
		AssessmentState: state,
		RiskScore:       riskText,
		SourceVersion:   ipqualityValue(result.Document.Head.Version),
		SourceURL:       "https://github.com/xykt/IPQuality",
		Metrics:         metricsForIPQuality(result),
		Reasons:         result.AssessmentReasons,
		TerminalHTML:    renderANSITerminalFragment(ipqualityTerminalSource(result)),
	}
	var output bytes.Buffer
	if err := ipqualityTemplate.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func metricsForIPQuality(result ipqualityResult) []metricRow {
	document := result.Document
	rows := []metricRow{
		{Name: "出口 IP", Value: ipqualityValue(document.Head.IP), Status: "已获取", State: stateGood},
		{Name: "连接方式", Value: protocolDisplayName(result.ProxyProtocol), Status: "已验证", State: stateGood},
		{Name: "ASN", Value: prefixASN(document.Info.ASN), Status: "信息", State: stateInfo},
		{Name: "网络组织", Value: ipqualityValue(document.Info.Organization), Status: "信息", State: stateInfo},
		{Name: "地理位置", Value: ipqualityLocation(document.Info), Status: "信息", State: stateInfo},
		{Name: "注册地区", Value: ipqualityPlaceText(document.Info.RegisteredRegion), Status: "信息", State: stateInfo},
		{Name: "时区", Value: ipqualityValue(document.Info.TimeZone), Status: "信息", State: stateInfo},
		{Name: "IP 类型", Value: ipqualityValue(document.Info.Type), Status: "信息", State: stateInfo},
	}

	for _, key := range orderedMapKeys(document.Type.Usage, []string{"IPinfo", "ipregistry", "ipapi", "AbuseIPDB", "IP2LOCATION"}) {
		rows = append(rows, metricRow{Name: "用途类型 · " + key, Value: ipqualityAny(document.Type.Usage[key]), Status: "数据库结果", State: stateInfo})
	}
	for _, key := range orderedMapKeys(document.Type.Company, []string{"IPinfo", "ipregistry", "ipapi"}) {
		rows = append(rows, metricRow{Name: "公司类型 · " + key, Value: ipqualityAny(document.Type.Company[key]), Status: "数据库结果", State: stateInfo})
	}
	for _, key := range orderedMapKeys(document.Score, []string{"IP2LOCATION", "SCAMALYTICS", "ipapi", "AbuseIPDB", "IPQS", "DBIP"}) {
		rows = append(rows, ipqualityScoreMetric(key, document.Score[key]))
	}
	for _, key := range orderedMapKeys(document.Factor, []string{"CountryCode", "Proxy", "Tor", "VPN", "Server", "Abuser", "Robot"}) {
		rows = append(rows, ipqualityFactorMetric(key, document.Factor[key]))
	}
	for _, key := range orderedMapKeys(document.Media, []string{"TikTok", "DisneyPlus", "Netflix", "Youtube", "AmazonPrimeVideo", "Reddit", "ChatGPT"}) {
		rows = append(rows, ipqualityMediaMetric(key, document.Media[key]))
	}
	for _, key := range orderedMapKeys(document.Mail, []string{"Port25", "Gmail", "Outlook", "Yahoo", "Apple", "QQ", "MailRU", "AOL", "GMX", "MailCOM", "163", "Sohu", "Sina"}) {
		if key == "DNSBlacklist" {
			continue
		}
		rows = append(rows, ipqualityMailMetric(key, document.Mail[key]))
	}
	if blacklist, ok := anyMap(document.Mail["DNSBlacklist"]); ok {
		rows = append(rows, ipqualityDNSBLMetric(blacklist))
	}
	return rows
}

func ipqualityScoreMetric(source string, value any) metricRow {
	score, ok := numericAny(value)
	if !ok {
		return metricRow{Name: "风险分数 · " + source, Value: "未返回", Status: "无数据", State: stateInfo}
	}
	score = normalizedIPQualityScore(score)
	state, status := stateGood, "低风险"
	if score >= 70 {
		state, status = stateBad, "高风险"
	} else if score >= 30 {
		state, status = stateWarning, "需复核"
	}
	return metricRow{Name: "风险分数 · " + source, Value: fmt.Sprintf("%.0f / 100", score), Status: status, State: state}
}

func ipqualityFactorMetric(category string, values map[string]any) metricRow {
	displayName := map[string]string{
		"CountryCode": "国家代码一致性",
		"Proxy":       "代理标记",
		"Tor":         "Tor 标记",
		"VPN":         "VPN 标记",
		"Server":      "机房 / 服务器标记",
		"Abuser":      "滥用记录",
		"Robot":       "机器人流量标记",
	}[category]
	if displayName == "" {
		displayName = category
	}
	if category == "CountryCode" {
		counts := make(map[string]int)
		for _, value := range values {
			text := ipqualityAny(value)
			if text != "未返回" {
				counts[text]++
			}
		}
		pairs := make([]string, 0, len(counts))
		for code, count := range counts {
			pairs = append(pairs, fmt.Sprintf("%s × %d", code, count))
		}
		sort.Strings(pairs)
		status, state := "一致", stateGood
		if len(counts) > 1 {
			status, state = "存在差异", stateWarning
		}
		if len(pairs) == 0 {
			pairs = append(pairs, "未返回")
			status, state = "无数据", stateInfo
		}
		return metricRow{Name: displayName, Value: strings.Join(pairs, "；"), Status: status, State: state}
	}

	positive := make([]string, 0)
	negative := 0
	unknown := 0
	for source, value := range values {
		flag, ok := boolAny(value)
		if !ok {
			unknown++
			continue
		}
		if flag {
			positive = append(positive, source)
		} else {
			negative++
		}
	}
	sort.Strings(positive)
	if len(positive) == 0 {
		return metricRow{
			Name:   displayName,
			Value:  fmt.Sprintf("0 个数据源标记；%d 个否定；%d 个未返回", negative, unknown),
			Status: "未发现",
			State:  stateGood,
		}
	}
	state, status := stateWarning, "需复核"
	if category == "Tor" || category == "Abuser" || category == "Robot" {
		state, status = stateBad, "高风险"
	}
	return metricRow{
		Name:   displayName,
		Value:  fmt.Sprintf("%d 个数据源标记：%s", len(positive), strings.Join(positive, "、")),
		Status: status,
		State:  state,
	}
}

func ipqualityMediaMetric(service string, value ipqualityMediaResult) metricRow {
	name := strings.NewReplacer("DisneyPlus", "Disney+", "Youtube", "YouTube", "AmazonPrimeVideo", "Amazon Prime Video").Replace(service)
	status := ipqualityValue(value.Status)
	details := make([]string, 0, 2)
	if text := ipqualityOptional(value.Region); text != "" {
		details = append(details, "地区 "+text)
	}
	if text := ipqualityOptional(value.Type); text != "" {
		details = append(details, "方式 "+text)
	}
	result := status
	if len(details) > 0 {
		result += "；" + strings.Join(details, "，")
	}
	state, label := stateWarning, "不可用"
	if strings.Contains(status, "解锁") || strings.Contains(strings.ToLower(status), "unlock") {
		state, label = stateGood, "可用"
	} else if status == "未返回" {
		state, label = stateInfo, "无数据"
	}
	return metricRow{Name: "服务解锁 · " + name, Value: result, Status: label, State: state}
}

func ipqualityMailMetric(provider string, value any) metricRow {
	name := provider
	if provider == "Port25" {
		name = "TCP 25 端口"
	}
	available, ok := boolAny(value)
	if !ok {
		return metricRow{Name: "邮件 · " + name, Value: "未返回", Status: "无数据", State: stateInfo}
	}
	if available {
		return metricRow{Name: "邮件 · " + name, Value: "可连接", Status: "可用", State: stateGood}
	}
	return metricRow{Name: "邮件 · " + name, Value: "不可连接或被限制", Status: "受限", State: stateWarning}
}

func ipqualityDNSBLMetric(values map[string]any) metricRow {
	total, _ := integerAny(values["Total"])
	clean, _ := integerAny(values["Clean"])
	marked, _ := integerAny(values["Marked"])
	blacklisted, _ := integerAny(values["Blacklisted"])
	state, status := stateGood, "未列入"
	if blacklisted > 0 {
		state, status = stateBad, "已列入"
	} else if marked > 0 {
		state, status = stateWarning, "有异常响应"
	}
	return metricRow{
		Name:   "DNSBL 黑名单",
		Value:  fmt.Sprintf("共 %d；干净 %d；异常 %d；明确列入 %d", total, clean, marked, blacklisted),
		Status: status,
		State:  state,
	}
}

func assessIPQuality(document ipqualityDocument) (string, []string) {
	high := false
	review := false
	reasons := make([]string, 0, 8)
	if score, source, ok := maxIPQualityScore(document.Score); ok {
		if score >= 70 {
			high = true
			reasons = append(reasons, fmt.Sprintf("%s 返回最高风险分数 %.0f/100", source, score))
		} else if score >= 30 {
			review = true
			reasons = append(reasons, fmt.Sprintf("%s 返回最高风险分数 %.0f/100", source, score))
		}
	}
	for _, category := range []string{"Proxy", "VPN", "Server", "Tor", "Abuser", "Robot"} {
		positive := 0
		for _, value := range document.Factor[category] {
			if flag, ok := boolAny(value); ok && flag {
				positive++
			}
		}
		if positive == 0 {
			continue
		}
		label := map[string]string{"Proxy": "代理", "VPN": "VPN", "Server": "机房/服务器", "Tor": "Tor", "Abuser": "滥用", "Robot": "机器人流量"}[category]
		reasons = append(reasons, fmt.Sprintf("%d 个数据库返回%s标记", positive, label))
		if category == "Tor" || category == "Abuser" || category == "Robot" {
			high = true
		} else {
			review = true
		}
	}
	if blacklist, ok := anyMap(document.Mail["DNSBlacklist"]); ok {
		if count, valid := integerAny(blacklist["Blacklisted"]); valid && count > 0 {
			high = true
			reasons = append(reasons, fmt.Sprintf("DNSBL 中有 %d 个数据库明确列入黑名单", count))
		}
	}
	if high {
		return "high risk / 高风险", reasons
	}
	if review {
		return "review needed / 建议复核", reasons
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "已返回的数据源中未发现主要高风险信号")
	}
	return "low risk / 低风险", reasons
}

func maxIPQualityScore(scores map[string]any) (float64, string, bool) {
	maximum := 0.0
	source := ""
	found := false
	for key, value := range scores {
		score, ok := numericAny(value)
		if !ok {
			continue
		}
		score = normalizedIPQualityScore(score)
		if !found || score > maximum {
			maximum, source, found = score, key, true
		}
	}
	return maximum, source, found
}

func buildIPQualityPlainText(document ipqualityDocument) string {
	var output strings.Builder
	fmt.Fprintln(&output, "IPQuality 原项目检测结果")
	fmt.Fprintln(&output, "========================")
	fmt.Fprintf(&output, "出口 IP: %s\n", ipqualityValue(document.Head.IP))
	fmt.Fprintf(&output, "ASN: %s\n", prefixASN(document.Info.ASN))
	fmt.Fprintf(&output, "组织: %s\n", ipqualityValue(document.Info.Organization))
	fmt.Fprintf(&output, "地区: %s\n", ipqualityLocation(document.Info))
	fmt.Fprintf(&output, "版本: %s\n", ipqualityValue(document.Head.Version))
	return strings.TrimSpace(output.String())
}

func ipqualityLocation(info ipqualityInfo) string {
	parts := make([]string, 0, 3)
	for _, value := range []string{info.City.Name, info.City.Subdivisions, info.Region.Name} {
		if text := ipqualityOptional(value); text != "" && !containsString(parts, text) {
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		return "未知"
	}
	return strings.Join(parts, "，")
}

func ipqualityPlaceText(place ipqualityPlace) string {
	name := ipqualityOptional(place.Name)
	code := ipqualityOptional(place.Code)
	if name == "" {
		name = code
	} else if code != "" {
		name += " (" + code + ")"
	}
	if name == "" {
		return "未返回"
	}
	return name
}

func prefixASN(value string) string {
	value = ipqualityValue(value)
	if value == "未返回" || strings.HasPrefix(strings.ToUpper(value), "AS") {
		return value
	}
	return "AS" + value
}

func ipqualityValue(value string) string {
	if value = ipqualityOptional(value); value != "" {
		return value
	}
	return "未返回"
}

func ipqualityOptional(value string) string {
	value = strings.TrimSpace(sanitize(value))
	if value == "" || strings.EqualFold(value, "null") || strings.EqualFold(value, "unknown") {
		return ""
	}
	return value
}

func ipqualityAny(value any) string {
	switch typed := value.(type) {
	case nil:
		return "未返回"
	case string:
		return ipqualityValue(typed)
	case bool:
		if typed {
			return "是"
		}
		return "否"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return sanitize(fmt.Sprint(value))
	}
}

func numericAny(value any) (float64, bool) {
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case float32:
		number = float64(typed)
	case int:
		number = float64(typed)
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		number = parsed
	case string:
		if ipqualityOptional(typed) == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(typed), "%"), 64)
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

var ipqualityTextScorePattern = regexp.MustCompile(`(?mi)^(IP2Location|Scamalytics|ipapi|AbuseIPDB|IPQS|DB-IP)[：:]\s*([0-9]+(?:\.[0-9]+)?)%?\|`)
var ipqualityMailPattern = regexp.MustCompile(`([+-])([A-Za-z0-9]+)`)

func enrichIPQualityDocumentFromText(document *ipqualityDocument, plainText string) {
	if document.Score == nil {
		document.Score = make(map[string]any)
	}
	aliases := map[string]string{
		"ip2location": "IP2LOCATION",
		"scamalytics": "SCAMALYTICS",
		"ipapi":       "ipapi",
		"abuseipdb":   "AbuseIPDB",
		"ipqs":        "IPQS",
		"db-ip":       "DBIP",
	}
	for _, match := range ipqualityTextScorePattern.FindAllStringSubmatch(plainText, -1) {
		key := aliases[strings.ToLower(match[1])]
		if _, valid := numericAny(document.Score[key]); valid {
			continue
		}
		document.Score[key] = match[2]
	}

	if document.Mail == nil {
		document.Mail = make(map[string]any)
	}
	for _, line := range strings.Split(plainText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "通信：") || strings.HasPrefix(trimmed, "通信:") {
			for _, match := range ipqualityMailPattern.FindAllStringSubmatch(trimmed, -1) {
				document.Mail[match[2]] = match[1] == "+"
			}
		}
		if strings.HasPrefix(trimmed, "本地25端口出站") {
			document.Mail["Port25"] = strings.Contains(trimmed, "开放") || strings.Contains(strings.ToLower(trimmed), "open")
		}
	}
}

func normalizedIPQualityScore(number float64) float64 {
	if number < 0 {
		return 0
	}
	if number > 100 {
		return 100
	}
	return number
}

func integerAny(value any) (int, bool) {
	number, ok := numericAny(value)
	if !ok {
		return 0, false
	}
	return int(math.Round(number)), true
}

func boolAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "1":
			return true, true
		case "false", "no", "0":
			return false, true
		}
	}
	return false, false
}

func anyMap(value any) (map[string]any, bool) {
	result, ok := value.(map[string]any)
	return result, ok
}

func orderedMapKeys[T any](values map[string]T, preferred []string) []string {
	keys := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, key := range preferred {
		if _, ok := values[key]; ok {
			keys = append(keys, key)
			seen[key] = struct{}{}
		}
	}
	remainder := make([]string, 0, len(values)-len(keys))
	for key := range values {
		if _, ok := seen[key]; !ok {
			remainder = append(remainder, key)
		}
	}
	sort.Strings(remainder)
	return append(keys, remainder...)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func netJoinHostPort(host string, port int) string {
	if port <= 0 {
		return sanitize(host)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", sanitize(host), port)
}

var ipqualityTemplate = template.Must(template.New("ipquality-report").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>IPQuality 完整检测结果</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#66717c;--line:#dce2e8;--panel:#fff;--canvas:#f3f5f7;--good:#137a5a;--warn:#9a6300;--bad:#b42318;--info:#285f9e}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.55 "Microsoft YaHei UI","Segoe UI",sans-serif;letter-spacing:0}
.shell{max-width:1120px;margin:0 auto;padding:26px 20px 44px}.top{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:16px}.brand{font-size:22px;font-weight:700}.eyebrow{font-size:12px;color:var(--info);font-weight:700;margin-bottom:2px}.meta{color:var(--muted);text-align:right}
.summary{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:10px;margin-bottom:14px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px 16px;min-width:0}.stat-label{font-size:12px;color:var(--muted);margin-bottom:5px}.stat-value{font-size:18px;font-weight:700;overflow-wrap:anywhere}.stat-sub{font-size:12px;color:var(--muted);margin-top:4px}
.state-good{color:var(--good)}.state-warning{color:var(--warn)}.state-bad{color:var(--bad)}.state-info{color:var(--info)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:14px}.panel-head{padding:12px 15px;border-bottom:1px solid var(--line);font-weight:700}
table{width:100%;border-collapse:collapse}th,td{padding:9px 15px;text-align:left;border-bottom:1px solid #edf0f3;vertical-align:top}th{font-size:12px;color:var(--muted);background:#fafbfc;font-weight:600}tr:last-child td{border-bottom:0}.metric{width:26%;font-weight:600}.value{overflow-wrap:anywhere}.status{width:100px;font-weight:700}.reasons{margin:14px 0 0;padding:12px 18px 12px 36px;background:#fff8e8;border:1px solid #eed596;border-radius:6px;color:#6f4a00}
pre{margin:0;padding:16px;overflow:auto;white-space:pre;background:#0c0c0c;color:#cccccc;font:13px/1.55 Consolas,"Cascadia Mono","Microsoft YaHei UI",monospace;max-height:760px;tab-size:4}.foot{display:flex;justify-content:space-between;gap:20px;color:var(--muted);font-size:12px;margin-top:14px}@media(max-width:720px){.summary{grid-template-columns:1fr}.top,.foot{align-items:flex-start;flex-direction:column}.meta{text-align:left}.metric{width:34%}th,td{padding:8px 10px}.status{width:76px}}
</style>
</head>
<body><main class="shell">
<header class="top"><div><div class="eyebrow">IPQUALITY · LOCAL REPORT</div><div class="brand">IPQuality 完整检测</div></div><div class="meta">{{.GeneratedAt}}<br>{{.ProxyAddress}} · {{.Protocol}}</div></header>
<section class="summary">
<div class="stat"><div class="stat-label">出口 IP</div><div class="stat-value">{{.ExitIP}}</div><div class="stat-sub">{{.Location}}</div></div>
<div class="stat"><div class="stat-label">本工具综合判断</div><div class="stat-value state-{{.AssessmentState}}">{{.Assessment}}</div><div class="stat-sub">保留原项目数据，结论仅作参考</div></div>
<div class="stat"><div class="stat-label">最高有效风险分数</div><div class="stat-value">{{.RiskScore}}</div><div class="stat-sub">不同数据库口径可能不同</div></div>
</section>
<section class="panel"><div class="panel-head">解析指标</div><table><thead><tr><th>指标</th><th>检测结果</th><th>状态</th></tr></thead><tbody>
{{range .Metrics}}<tr><td class="metric">{{.Name}}</td><td class="value">{{.Value}}</td><td class="status state-{{.State}}">{{.Status}}</td></tr>{{end}}
</tbody></table></section>
{{if .Reasons}}<ul class="reasons">{{range .Reasons}}<li>{{.}}</li>{{end}}</ul>{{end}}
<section class="panel"><div class="panel-head">IPQuality 原始文本报告</div><pre>{{.TerminalHTML}}</pre></section>
<footer class="foot"><span>上游：{{.SourceURL}} · {{.SourceVersion}}</span><span>原始 JSON 与文本报告保存在本文件同目录</span></footer>
</main></body></html>`))
