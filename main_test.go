package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  config
		wantErr bool
	}{
		{name: "valid", config: config{ProxyHost: "127.0.0.1", ProxyPort: 7897, Timeout: 20}},
		{name: "valid hostname", config: config{ProxyHost: "localhost", ProxyPort: 8080, Timeout: 10}},
		{name: "valid socks5", config: config{ProxyHost: "127.0.0.1", ProxyPort: 1080, Protocol: protocolSOCKS5, Timeout: 20}},
		{name: "valid direct without proxy settings", config: config{Direct: true, Timeout: 20}},
		{name: "invalid host", config: config{ProxyHost: "127.0.0.1/path", ProxyPort: 7897, Timeout: 20}, wantErr: true},
		{name: "invalid port", config: config{ProxyHost: "127.0.0.1", ProxyPort: 70000, Timeout: 20}, wantErr: true},
		{name: "short timeout", config: config{ProxyHost: "127.0.0.1", ProxyPort: 7897, Timeout: 1}, wantErr: true},
		{name: "invalid protocol", config: config{ProxyHost: "127.0.0.1", ProxyPort: 7897, Protocol: "ftp", Timeout: 20}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig(test.config)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateConfig() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestRiskPercent(t *testing.T) {
	if got := riskPercent(0.42); got != 42 {
		t.Fatalf("riskPercent(0.42) = %v, want 42", got)
	}
	if got := riskPercent(75); got != 75 {
		t.Fatalf("riskPercent(75) = %v, want 75", got)
	}
	if got := riskPercent(150); got != 100 {
		t.Fatalf("riskPercent(150) = %v, want 100", got)
	}
}

func TestSanitizeRemovesControlCharacters(t *testing.T) {
	if got := sanitize("safe\x1b[31m\ntext"); got != "safe[31mtext" {
		t.Fatalf("sanitize() = %q", got)
	}
}

func TestAssessUsesIndependentRecommendation(t *testing.T) {
	assessment, reasons := assess(securityData{}, checkResult{Available: true, Value: "block"})
	if assessment != "review needed / 建议复核" {
		t.Fatalf("assessment = %q", assessment)
	}
	if len(reasons) != 1 {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestParseKeyValues(t *testing.T) {
	values := parseKeyValues("loc=JP\nwarp=off\n")
	if values["loc"] != "JP" || values["warp"] != "off" {
		t.Fatalf("parseKeyValues() = %v", values)
	}
}

func TestNormalizeProtocol(t *testing.T) {
	tests := map[string]string{
		"":       protocolAuto,
		"mixed":  protocolAuto,
		"HTTP":   protocolHTTP,
		"socks5": protocolSOCKS5,
		"DIRECT": protocolDirect,
	}
	for input, expected := range tests {
		if actual := normalizeProtocol(input); actual != expected {
			t.Fatalf("normalizeProtocol(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestNewConnectionClientDirectDisablesProxy(t *testing.T) {
	cfg := defaultConfig()
	cfg.Direct = true
	client, err := newConnectionClient(cfg, protocolDirect)
	if err != nil {
		t.Fatalf("newConnectionClient() error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatalf("direct client retained a proxy resolver")
	}
}

func TestNormalizeCheckMode(t *testing.T) {
	tests := map[string]string{
		"":          checkModeFull,
		"fast":      checkModeQuick,
		"quick":     checkModeQuick,
		"full":      checkModeFull,
		"ipquality": checkModeFull,
	}
	for input, expected := range tests {
		if actual := normalizeCheckMode(input); actual != expected {
			t.Fatalf("normalizeCheckMode(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestDefaultConfigUsesFullCheck(t *testing.T) {
	if mode := normalizeCheckMode(defaultConfig().CheckMode); mode != checkModeFull {
		t.Fatalf("default check mode = %q, want %q", mode, checkModeFull)
	}
}

func TestPerformCheckHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := performCheck(ctx, defaultConfig(), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("performCheck() error = %v, want context.Canceled", err)
	}
}

func TestSaveAndLoadLatestReport(t *testing.T) {
	directory := t.TempDir()
	cfg := defaultConfig()
	result := report{
		GeneratedAt:   time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC),
		Version:       "test",
		ProxyHost:     cfg.ProxyHost,
		ProxyPort:     cfg.ProxyPort,
		ProxyProtocol: protocolSOCKS5,
		LatencyMS:     123,
		Intel: intelData{
			IP:      "203.0.113.10",
			Version: "IPv4",
			Location: locationData{
				Country:     "Test <Country>",
				CountryCode: "TC",
			},
			Network: networkData{ISP: "Example & ISP", ASN: "AS64500"},
		},
		Blackbox:   checkResult{Available: true, Value: "allow"},
		ChatGPT:    checkResult{Available: true, Value: "JP"},
		Google:     checkResult{Available: true, Value: "reachable"},
		Assessment: "low risk / 低风险",
		AssessmentReasons: []string{
			"no major risk signal was returned",
		},
	}

	files, err := saveLatestSuccess(directory, cfg, result)
	if err != nil {
		t.Fatalf("saveLatestSuccess() error = %v", err)
	}
	if filepath.Base(files.JSON) != "ipcheck-203.0.113.10-result.json" {
		t.Fatalf("saved JSON name = %q", filepath.Base(files.JSON))
	}
	session, err := loadLatestSession(files.JSON)
	if err != nil {
		t.Fatalf("loadLatestSession() error = %v", err)
	}
	if !session.Success || session.Result == nil || session.Result.ProxyProtocol != protocolSOCKS5 {
		t.Fatalf("loaded session = %#v", session)
	}

	htmlContent, err := os.ReadFile(files.HTML)
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	htmlText := string(htmlContent)
	if !strings.Contains(htmlText, "203.0.113.10") || !strings.Contains(htmlText, "SOCKS5") {
		t.Fatalf("HTML report is missing expected result fields")
	}
	if strings.Contains(htmlText, "Test <Country>") || strings.Contains(htmlText, "Example & ISP") {
		t.Fatalf("HTML report did not escape API-provided text")
	}
}

func TestQuickReportsRetainDifferentIPsAndReplaceSameIP(t *testing.T) {
	directory := t.TempDir()
	cfg := defaultConfig()
	first := report{
		GeneratedAt:   time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC),
		ProxyProtocol: protocolHTTP,
		Intel: intelData{
			IP:      "203.0.113.10",
			Version: "IPv4",
			Network: networkData{ISP: "first"},
		},
	}
	secondIP := first
	secondIP.GeneratedAt = time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC)
	secondIP.Intel.IP = "198.51.100.20"
	secondIP.Intel.Network.ISP = "second IP"
	latestFirstIP := first
	latestFirstIP.GeneratedAt = time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC)
	latestFirstIP.Intel.Network.ISP = "latest first IP"

	if _, err := saveLatestSuccess(directory, cfg, first); err != nil {
		t.Fatal(err)
	}
	if _, err := saveLatestSuccess(directory, cfg, secondIP); err != nil {
		t.Fatal(err)
	}
	firstFiles, err := saveLatestSuccess(directory, cfg, latestFirstIP)
	if err != nil {
		t.Fatal(err)
	}

	jsonFiles, err := filepath.Glob(filepath.Join(directory, "ipcheck-*-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(jsonFiles) != 2 {
		t.Fatalf("saved quick report groups = %d, want 2: %v", len(jsonFiles), jsonFiles)
	}
	firstSession, err := loadLatestSession(firstFiles.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if firstSession.Result == nil || firstSession.Result.Intel.Network.ISP != "latest first IP" {
		t.Fatalf("same-IP report was not replaced: %#v", firstSession.Result)
	}
	latest, latestFiles, err := loadLatestQuickSession(directory)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Result == nil || latest.Result.Intel.IP != "203.0.113.10" || latestFiles.JSON != firstFiles.JSON {
		t.Fatalf("latest quick report = %#v, files = %#v", latest.Result, latestFiles)
	}
}

func TestLoadLatestQuickSessionSupportsLegacyFilename(t *testing.T) {
	directory := t.TempDir()
	result := report{
		GeneratedAt:   time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC),
		ProxyProtocol: protocolHTTP,
		Intel:         intelData{IP: "203.0.113.30", Version: "IPv4"},
	}
	legacyFiles := quickReportFilesFromJSON(filepath.Join(directory, "ipcheck-last-result.json"))
	if err := saveLatestSession(directory, savedSession{
		Success:     true,
		GeneratedAt: result.GeneratedAt,
		Config:      defaultConfig(),
		Result:      &result,
	}, legacyFiles); err != nil {
		t.Fatal(err)
	}

	loaded, files, err := loadLatestQuickSession(directory)
	if err != nil {
		t.Fatal(err)
	}
	migratedFiles, err := quickReportFilesForIP(directory, result.Intel.IP)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Result == nil || loaded.Result.Intel.IP != result.Intel.IP || files != migratedFiles {
		t.Fatalf("legacy quick report was not restored: %#v, %#v", loaded.Result, files)
	}
	if _, err := os.Stat(legacyFiles.JSON); !os.IsNotExist(err) {
		t.Fatalf("legacy quick JSON still exists after migration: %v", err)
	}
}

func TestLegacyQuickMigrationKeepsNewerIPNamedReport(t *testing.T) {
	directory := t.TempDir()
	cfg := defaultConfig()
	newer := report{
		GeneratedAt:   time.Date(2026, 7, 18, 2, 0, 0, 0, time.UTC),
		ProxyProtocol: protocolHTTP,
		Intel: intelData{
			IP:      "203.0.113.50",
			Version: "IPv4",
			Network: networkData{ISP: "newer"},
		},
	}
	if _, err := saveLatestSuccess(directory, cfg, newer); err != nil {
		t.Fatal(err)
	}
	older := newer
	older.GeneratedAt = time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	older.Intel.Network.ISP = "older legacy"
	legacyFiles := quickReportFilesFromJSON(filepath.Join(directory, "ipcheck-last-result.json"))
	if err := saveLatestSession(directory, savedSession{
		Success:     true,
		GeneratedAt: older.GeneratedAt,
		Config:      cfg,
		Result:      &older,
	}, legacyFiles); err != nil {
		t.Fatal(err)
	}

	loaded, _, err := loadLatestQuickSession(directory)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Result == nil || loaded.Result.Intel.Network.ISP != "newer" {
		t.Fatalf("older legacy report replaced the newer report: %#v", loaded.Result)
	}
	if _, err := os.Stat(legacyFiles.JSON); !os.IsNotExist(err) {
		t.Fatalf("older legacy JSON still exists after deduplication: %v", err)
	}
}

func TestReportIPTokenSupportsIPv6(t *testing.T) {
	token, err := reportIPToken("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if token != "2001-db8--1" {
		t.Fatalf("IPv6 report token = %q", token)
	}
}

func TestMetricsContainAtLeastSixIndicators(t *testing.T) {
	value := report{
		ProxyProtocol: protocolHTTP,
		Intel: intelData{
			IP:      "203.0.113.10",
			Version: "IPv4",
		},
	}
	if count := len(metricsForReport(value)); count < 6 {
		t.Fatalf("metricsForReport() returned %d indicators, want at least 6", count)
	}
}

func TestQuickReportLabelsDirectConnection(t *testing.T) {
	cfg := defaultConfig()
	cfg.Direct = true
	result := report{
		GeneratedAt:   time.Date(2026, 7, 18, 3, 0, 0, 0, time.UTC),
		ProxyHost:     cfg.ProxyHost,
		ProxyPort:     cfg.ProxyPort,
		ProxyProtocol: protocolDirect,
		Intel:         intelData{IP: "203.0.113.11", Version: "IPv4"},
	}
	htmlContent, err := renderSessionHTML(savedSession{Success: true, GeneratedAt: result.GeneratedAt, Config: cfg, Result: &result})
	if err != nil {
		t.Fatalf("renderSessionHTML() error = %v", err)
	}
	htmlText := string(htmlContent)
	if !strings.Contains(htmlText, "未使用代理") || !strings.Contains(htmlText, "本机直连") {
		t.Fatalf("direct connection labels are missing from HTML report")
	}
	if strings.Contains(htmlText, "127.0.0.1:7897") {
		t.Fatalf("direct report incorrectly displays the configured proxy address")
	}
}
