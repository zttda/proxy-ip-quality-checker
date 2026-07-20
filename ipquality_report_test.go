package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleIPQualityJSON = `{
  "Head": {"IP":"203.0.113.24","GitHub":"https://github.com/xykt/IPQuality","Time":"2026-07-18 12:00:00 CST","Version":"v2026-03-29"},
  "Info": {
    "ASN":"64500","Organization":"Example <Network>","TimeZone":"Asia/Tokyo","Type":"广播IP",
    "City":{"Name":"东京"},"Region":{"Code":"JP","Name":"日本"},"RegisteredRegion":{"Code":"US","Name":"美国"}
  },
  "Type": {"Usage":{"IPinfo":"机房","ipregistry":"机房"},"Company":{"IPinfo":"商业"}},
  "Score": {"IPQS":"84","AbuseIPDB":"0","SCAMALYTICS":"null"},
  "Factor": {
    "CountryCode":{"IPQS":"JP","ipregistry":"JP"},
    "Proxy":{"IPQS":true,"ipregistry":false},"Tor":{"IPQS":false},"VPN":{"IPQS":true},
    "Server":{"ipregistry":true},"Abuser":{"IPQS":false},"Robot":{"IPQS":false}
  },
  "Media": {"Netflix":{"Status":"解锁","Region":"JP","Type":"DNS"},"ChatGPT":{"Status":"失败","Region":"","Type":""}},
  "Mail": {"Port25":false,"Gmail":true,"DNSBlacklist":{"Total":439,"Clean":438,"Marked":1,"Blacklisted":0}}
}`

func TestParseIPQualityDocumentAndMetrics(t *testing.T) {
	document, err := parseIPQualityDocument([]byte(sampleIPQualityJSON))
	if err != nil {
		t.Fatalf("parseIPQualityDocument() error = %v", err)
	}
	result := ipqualityResult{Document: document, ProxyProtocol: protocolHTTP}
	result.Assessment, result.AssessmentReasons = assessIPQuality(document)
	if !strings.HasPrefix(result.Assessment, "high") {
		t.Fatalf("assessment = %q, want high risk", result.Assessment)
	}
	metrics := metricsForIPQuality(result)
	if len(metrics) < 20 {
		t.Fatalf("metricsForIPQuality() returned %d metrics, want at least 20", len(metrics))
	}
	foundDNSBL := false
	for _, metric := range metrics {
		if metric.Name == "DNSBL 黑名单" {
			foundDNSBL = strings.Contains(metric.Value, "共 439")
		}
	}
	if !foundDNSBL {
		t.Fatalf("DNSBL metric did not preserve the total count")
	}
}

func TestSaveAndLoadIPQualityReport(t *testing.T) {
	document, err := parseIPQualityDocument([]byte(sampleIPQualityJSON))
	if err != nil {
		t.Fatal(err)
	}
	assessment, reasons := assessIPQuality(document)
	result := ipqualityResult{
		GeneratedAt:       time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC),
		ProxyHost:         "127.0.0.1",
		ProxyPort:         7897,
		ProxyProtocol:     protocolSOCKS5,
		Document:          document,
		RawJSON:           []byte(sampleIPQualityJSON),
		TerminalText:      "\x1b[31m原始报告 <unsafe>\x1b[0m",
		PlainText:         "原始报告 <unsafe>",
		Assessment:        assessment,
		AssessmentReasons: reasons,
	}
	directory := t.TempDir()
	files, err := saveLatestIPQuality(directory, result)
	if err != nil {
		t.Fatalf("saveLatestIPQuality() error = %v", err)
	}
	if filepath.Base(files.HTML) != "ipquality-203.0.113.24-result.html" {
		t.Fatalf("saved HTML name = %q", filepath.Base(files.HTML))
	}
	loaded, loadedFiles, err := loadLatestIPQuality(directory, defaultConfig())
	if err != nil {
		t.Fatalf("loadLatestIPQuality() error = %v", err)
	}
	if loadedFiles != files {
		t.Fatalf("loaded files = %#v, want %#v", loadedFiles, files)
	}
	if loaded.Document.Head.IP != "203.0.113.24" || loaded.ProxyProtocol != protocolSOCKS5 {
		t.Fatalf("loaded result = %#v", loaded)
	}
	htmlContent, err := os.ReadFile(files.HTML)
	if err != nil {
		t.Fatal(err)
	}
	htmlText := string(htmlContent)
	if !strings.Contains(htmlText, "IPQuality 原始文本报告") || strings.Contains(htmlText, "Example <Network>") || strings.Contains(htmlText, "<unsafe>") {
		t.Fatalf("HTML report is missing content or failed to escape untrusted values")
	}
	rawContent, err := os.ReadFile(files.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawContent), `"Head"`) || strings.Contains(string(rawContent), `"_ProxyIPCheck"`) {
		t.Fatalf("saved JSON is not the unwrapped upstream document")
	}
	originalContent, err := os.ReadFile(files.OriginalHTML)
	if err != nil {
		t.Fatal(err)
	}
	originalHTML := string(originalContent)
	if !strings.Contains(originalHTML, "background:#0c0c0c") || !strings.Contains(originalHTML, "color:#c50f1f") {
		t.Fatalf("standalone original report did not preserve the terminal palette")
	}
	if strings.Contains(originalHTML, "<unsafe>") || !strings.Contains(originalHTML, "&lt;unsafe&gt;") {
		t.Fatalf("standalone original report did not escape terminal text")
	}
}

func TestIPQualityReportsRetainDifferentIPsAndReplaceSameIP(t *testing.T) {
	directory := t.TempDir()
	first := sampleIPQualityResultForIP(t, "203.0.113.24", time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC))
	secondIP := sampleIPQualityResultForIP(t, "198.51.100.25", time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC))
	latestFirstIP := sampleIPQualityResultForIP(t, "203.0.113.24", time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC))
	latestFirstIP.PlainText = "latest report for first IP"

	if _, err := saveLatestIPQuality(directory, first); err != nil {
		t.Fatal(err)
	}
	if _, err := saveLatestIPQuality(directory, secondIP); err != nil {
		t.Fatal(err)
	}
	firstFiles, err := saveLatestIPQuality(directory, latestFirstIP)
	if err != nil {
		t.Fatal(err)
	}

	jsonFiles, err := filepath.Glob(filepath.Join(directory, "ipquality-*-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(jsonFiles) != 2 {
		t.Fatalf("saved IPQuality report groups = %d, want 2: %v", len(jsonFiles), jsonFiles)
	}
	textContent, err := os.ReadFile(firstFiles.Text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(textContent), "latest report for first IP") {
		t.Fatalf("same-IP text report was not replaced: %q", textContent)
	}
	latest, latestFiles, err := loadLatestIPQuality(directory, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if latest.Document.Head.IP != "203.0.113.24" || latestFiles != firstFiles {
		t.Fatalf("latest IPQuality report = %s, files = %#v", latest.Document.Head.IP, latestFiles)
	}
}

func TestLoadLatestIPQualitySupportsLegacyFilenames(t *testing.T) {
	directory := t.TempDir()
	result := sampleIPQualityResultForIP(t, "203.0.113.40", time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC))
	currentFiles, err := saveLatestIPQuality(directory, result)
	if err != nil {
		t.Fatal(err)
	}
	legacyFiles := ipqualityReportFilesFromJSON(filepath.Join(directory, "ipquality-last-result.json"))
	filePairs := [][2]string{
		{currentFiles.HTML, legacyFiles.HTML},
		{currentFiles.OriginalHTML, legacyFiles.OriginalHTML},
		{currentFiles.JSON, legacyFiles.JSON},
		{currentFiles.Text, legacyFiles.Text},
		{currentFiles.Metadata, legacyFiles.Metadata},
	}
	for _, pair := range filePairs {
		if err := os.Rename(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}

	loaded, files, err := loadLatestIPQuality(directory, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	migratedFiles, err := ipqualityReportFilesForIP(directory, result.Document.Head.IP)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Document.Head.IP != result.Document.Head.IP || files != migratedFiles {
		t.Fatalf("legacy IPQuality report was not restored: %s, %#v", loaded.Document.Head.IP, files)
	}
	if _, err := os.Stat(legacyFiles.JSON); !os.IsNotExist(err) {
		t.Fatalf("legacy IPQuality JSON still exists after migration: %v", err)
	}
}

func sampleIPQualityResultForIP(t *testing.T, ip string, generatedAt time.Time) ipqualityResult {
	t.Helper()
	rawJSON := strings.Replace(sampleIPQualityJSON, "203.0.113.24", ip, 1)
	document, err := parseIPQualityDocument([]byte(rawJSON))
	if err != nil {
		t.Fatal(err)
	}
	assessment, reasons := assessIPQuality(document)
	return ipqualityResult{
		GeneratedAt:       generatedAt,
		ProxyHost:         "127.0.0.1",
		ProxyPort:         7897,
		ProxyProtocol:     protocolHTTP,
		Document:          document,
		RawJSON:           []byte(rawJSON),
		TerminalText:      "sample terminal report",
		PlainText:         "sample plain report",
		Assessment:        assessment,
		AssessmentReasons: reasons,
	}
}

func TestIPQualityDirectModeOmitsProxyArgument(t *testing.T) {
	cfg := defaultConfig()
	cfg.Direct = true
	proxyURL := ipqualityProxyURL(cfg, protocolDirect)
	if proxyURL != "" {
		t.Fatalf("ipqualityProxyURL() = %q, want empty for direct mode", proxyURL)
	}
	args := ipqualityCommandArgs(protocolDirect, proxyURL, "result.json")
	for index, argument := range args {
		if argument == "-x" {
			t.Fatalf("direct command contains proxy option at index %d: %v", index, args)
		}
	}
}

func TestIPQualityProxyModeKeepsProxyArgument(t *testing.T) {
	cfg := defaultConfig()
	proxyURL := ipqualityProxyURL(cfg, protocolHTTP)
	args := ipqualityCommandArgs(protocolHTTP, proxyURL, "result.json")
	if !containsString(args, "-x") || !containsString(args, proxyURL) {
		t.Fatalf("proxy command is missing its proxy option: %v", args)
	}
}

func TestIPQualityEnvironmentRemovesInheritedProxyVariables(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:2")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:3")
	for _, item := range ipqualityEnvironment(t.TempDir(), "") {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY":
			t.Fatalf("inherited proxy variable leaked into runtime: %s", item)
		}
	}
}

func TestIPQualityHTMLLabelsDirectConnection(t *testing.T) {
	document, err := parseIPQualityDocument([]byte(sampleIPQualityJSON))
	if err != nil {
		t.Fatal(err)
	}
	content, err := renderIPQualityHTML(ipqualityResult{
		GeneratedAt:   time.Date(2026, 7, 18, 4, 0, 0, 0, time.UTC),
		ProxyHost:     "127.0.0.1",
		ProxyPort:     7897,
		ProxyProtocol: protocolDirect,
		Document:      document,
	})
	if err != nil {
		t.Fatalf("renderIPQualityHTML() error = %v", err)
	}
	htmlText := string(content)
	if !strings.Contains(htmlText, "未使用代理") || !strings.Contains(htmlText, "本机直连") {
		t.Fatalf("direct connection labels are missing from IPQuality report")
	}
	if strings.Contains(htmlText, "127.0.0.1:7897") {
		t.Fatalf("direct IPQuality report incorrectly displays the configured proxy address")
	}
}

func TestRenderANSITerminalFragmentPreservesColorsAndEscapesText(t *testing.T) {
	fragment := string(renderANSITerminalFragment("plain \x1b[1;92mgreen <tag>\x1b[0m end"))
	if !strings.Contains(fragment, "color:#16c60c") || !strings.Contains(fragment, "font-weight:700") {
		t.Fatalf("ANSI style was not preserved: %s", fragment)
	}
	if strings.Contains(fragment, "<tag>") || !strings.Contains(fragment, "&lt;tag&gt;") {
		t.Fatalf("terminal text was not escaped: %s", fragment)
	}
	if strings.Contains(fragment, "\x1b") {
		t.Fatalf("ANSI control bytes leaked into HTML: %q", fragment)
	}
}

func TestRenderANSITerminalFragmentUsesTerminalCarriageReturnSemantics(t *testing.T) {
	fragment := string(renderANSITerminalFragment("\n\x1b[2J\rfirst\n\r\x1b[31msecond\x1b[0m\n"))
	if strings.HasPrefix(fragment, "\n") || strings.Contains(fragment, "first\n\n") {
		t.Fatalf("terminal control sequences introduced blank lines: %q", fragment)
	}
	if !strings.Contains(fragment, "first\n") || !strings.Contains(fragment, "color:#c50f1f") {
		t.Fatalf("terminal content or color was lost: %q", fragment)
	}
}

func TestCleanIPQualityTextRemovesANSI(t *testing.T) {
	got := cleanIPQualityText("\x1b[31m风险\x1b[0m\r\n\r\n结果")
	if got != "风险\n\n结果" {
		t.Fatalf("cleanIPQualityText() = %q", got)
	}
}

func TestEnrichIPQualityDocumentFromText(t *testing.T) {
	document := ipqualityDocument{
		Score: map[string]any{"IPQS": "null", "ipapi": "0.85%"},
		Mail:  map[string]any{"Gmail": false, "QQ": false},
	}
	enrichIPQualityDocumentFromText(&document, "IPQS： 94|高风险\nipapi： 0.85%|低风险\n通信：-Gmail+QQ\n本地25端口出站：阻断")
	if score, _, ok := maxIPQualityScore(document.Score); !ok || score != 94 {
		t.Fatalf("enriched max score = %v, %v", score, ok)
	}
	if gmail, _ := boolAny(document.Mail["Gmail"]); gmail {
		t.Fatalf("Gmail should remain unavailable")
	}
	if qq, _ := boolAny(document.Mail["QQ"]); !qq {
		t.Fatalf("QQ should be enriched as available")
	}
}
