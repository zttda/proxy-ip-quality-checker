package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	xproxy "golang.org/x/net/proxy"
)

var version = "dev"

const (
	intelEndpoint    = "https://whatismyip.ai/api/ip"
	blackboxEndpoint = "https://blackbox.ipinfo.app/api/v1/"
	chatGPTEndpoint  = "https://chatgpt.com/cdn-cgi/trace"
	googleEndpoint   = "https://www.google.com/generate_204"
	maxResponseBytes = 2 << 20
	protocolAuto     = "auto"
	protocolHTTP     = "http"
	protocolSOCKS5   = "socks5"
	protocolDirect   = "direct"
	checkModeQuick   = "quick"
	checkModeFull    = "ipquality"
)

type config struct {
	ProxyHost   string `json:"proxyHost"`
	ProxyPort   int    `json:"proxyPort"`
	Protocol    string `json:"proxyProtocol"`
	Direct      bool   `json:"directConnection"`
	CheckMode   string `json:"checkMode"`
	Timeout     int    `json:"timeoutSeconds"`
	PauseOnExit bool   `json:"pauseOnExit"`
}

type intelResponse struct {
	Success bool      `json:"success"`
	Data    intelData `json:"data"`
}

type intelData struct {
	IP       string       `json:"ip"`
	Version  string       `json:"version"`
	Location locationData `json:"location"`
	Network  networkData  `json:"network"`
	Security securityData `json:"security"`
}

type locationData struct {
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Timezone    string  `json:"timezone"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type networkData struct {
	ISP            string `json:"isp"`
	Organization   string `json:"org"`
	ASN            string `json:"asn"`
	ConnectionType string `json:"connectionType"`
}

type securityData struct {
	Score         float64 `json:"score"`
	IsVPN         bool    `json:"isVpn"`
	IsProxy       bool    `json:"isProxy"`
	IsTor         bool    `json:"isTor"`
	IsHosting     bool    `json:"isHosting"`
	IsBlacklisted bool    `json:"isBlacklisted"`
}

type checkResult struct {
	Available bool   `json:"available"`
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
}

type report struct {
	GeneratedAt       time.Time   `json:"generatedAt"`
	Version           string      `json:"version"`
	ProxyHost         string      `json:"proxyHost"`
	ProxyPort         int         `json:"proxyPort"`
	ProxyProtocol     string      `json:"proxyProtocol"`
	LatencyMS         int64       `json:"latencyMs"`
	Intel             intelData   `json:"intel"`
	Blackbox          checkResult `json:"independentReputation"`
	ChatGPT           checkResult `json:"chatGPT"`
	Google            checkResult `json:"google"`
	Assessment        string      `json:"assessment"`
	AssessmentReasons []string    `json:"assessmentReasons"`
}

func cliMain() {
	initConsole()

	noPause := flag.Bool("no-pause", false, "do not wait for Enter before exiting")
	showVersion := flag.Bool("version", false, "print version and exit")
	configFlag := flag.String("config", "", "path to config.json")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	configPath, err := resolveConfigPath(*configFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	cfg, usedDefaults, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		pauseIfNeeded(true, *noPause)
		os.Exit(1)
	}

	if usedDefaults {
		fmt.Printf("Config not found; using default proxy 127.0.0.1:7897.\n")
	}

	exitCode := run(cfg, configPath)
	pauseIfNeeded(cfg.PauseOnExit, *noPause)
	os.Exit(exitCode)
}

func defaultConfig() config {
	return config{
		ProxyHost:   "127.0.0.1",
		ProxyPort:   7897,
		Protocol:    protocolAuto,
		Direct:      false,
		CheckMode:   checkModeFull,
		Timeout:     20,
		PauseOnExit: true,
	}
}

func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		absolute, err := filepath.Abs(explicit)
		if err != nil {
			return "", fmt.Errorf("resolve config path: %w", err)
		}
		return absolute, nil
	}

	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(executable), "config.json"), nil
}

func loadConfig(path string) (config, bool, error) {
	cfg := defaultConfig()
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, true, nil
	}
	if err != nil {
		return config{}, false, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return config{}, false, fmt.Errorf("parse config: %w", err)
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, false, err
	}
	return cfg, false, nil
}

func validateConfig(cfg config) error {
	if !cfg.Direct {
		if net.ParseIP(cfg.ProxyHost) == nil && !validHostname(cfg.ProxyHost) {
			return errors.New("proxyHost must be an IPv4 address or hostname")
		}
		if cfg.ProxyPort < 1 || cfg.ProxyPort > 65535 {
			return errors.New("proxyPort must be between 1 and 65535")
		}
	}
	if cfg.Timeout < 5 || cfg.Timeout > 120 {
		return errors.New("timeoutSeconds must be between 5 and 120")
	}
	switch normalizeProtocol(cfg.Protocol) {
	case protocolAuto, protocolHTTP, protocolSOCKS5:
	default:
		return errors.New("proxyProtocol must be auto, http, or socks5")
	}
	switch normalizeCheckMode(cfg.CheckMode) {
	case checkModeQuick, checkModeFull:
	default:
		return errors.New("checkMode must be quick or ipquality")
	}
	return nil
}

func normalizeProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "mixed" {
		return protocolAuto
	}
	return value
}

func configConnectionProtocol(cfg config) string {
	if cfg.Direct {
		return protocolDirect
	}
	return normalizeProtocol(cfg.Protocol)
}

func configConnectionSummary(cfg config) string {
	protocol := configConnectionProtocol(cfg)
	if protocol == protocolDirect {
		return "本机直连（未使用代理）"
	}
	return net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort)) + "，" + protocolDisplayName(protocol)
}

func normalizeCheckMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "full" {
		return checkModeFull
	}
	if value == "fast" {
		return checkModeQuick
	}
	return value
}

func validHostname(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func run(cfg config, configPath string) int {
	fmt.Printf("Proxy IP Quality Check %s\n", version)
	if cfg.Direct {
		fmt.Println("Connection: " + configConnectionSummary(cfg))
	} else {
		fmt.Printf("Proxy: %s:%d (%s)\n", cfg.ProxyHost, cfg.ProxyPort, protocolDisplayName(normalizeProtocol(cfg.Protocol)))
	}
	fmt.Printf("Mode: %s\n\n", checkModeDisplayNameForCLI(cfg.CheckMode))

	if normalizeCheckMode(cfg.CheckMode) == checkModeFull {
		return runIPQualityCLI(cfg, filepath.Dir(configPath))
	}

	result, err := performCheck(context.Background(), cfg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		if saveErr := saveLatestFailure(filepath.Dir(configPath), cfg, err); saveErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not save failure report: %v\n", saveErr)
		}
		return 1
	}

	printReport(result)
	files, saveErr := saveLatestSuccess(filepath.Dir(configPath), cfg, result)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not save result files: %v\n", saveErr)
	} else {
		fmt.Printf("\nSaved report: %s\n", files.HTML)
	}
	return 0
}

func runIPQualityCLI(cfg config, directory string) int {
	result, err := performIPQualityCheck(context.Background(), directory, cfg, func(percent int, message string) {
		fmt.Fprintf(os.Stderr, "[%3d%%] %s\n", percent, message)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		if saveErr := saveIPQualityFailure(directory, err); saveErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not save failure details: %v\n", saveErr)
		}
		return 1
	}
	files, saveErr := saveLatestIPQuality(directory, result)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "ERROR: could not save IPQuality reports: %v\n", saveErr)
		return 1
	}
	fmt.Println(result.PlainText)
	fmt.Printf("\nSaved report: %s\n", files.HTML)
	return 0
}

func checkModeDisplayNameForCLI(mode string) string {
	if normalizeCheckMode(mode) == checkModeFull {
		return "IPQuality full / IPQuality 完整检测"
	}
	return "quick / 快速检测"
}

type progressFunc func(percent int, message string)

func performCheck(parent context.Context, cfg config, progress progressFunc) (report, error) {
	if err := validateConfig(cfg); err != nil {
		return report{}, err
	}
	cfg.Protocol = normalizeProtocol(cfg.Protocol)
	notifyProgress(progress, 5, "正在连接检测服务")

	client, intel, usedProtocol, latency, err := connectAndFetchIntel(parent, cfg, progress)
	if err != nil {
		return report{}, fmt.Errorf("网络连接或公网 IP 查询失败: %w", err)
	}
	defer client.CloseIdleConnections()

	notifyProgress(progress, 50, "正在查询信誉与可用性")
	type auxiliaryResult struct {
		name  string
		value checkResult
	}
	results := make(chan auxiliaryResult, 3)
	go func() {
		results <- auxiliaryResult{"blackbox", checkBlackbox(parent, client, intel.Data.IP, cfg.Timeout)}
	}()
	go func() {
		results <- auxiliaryResult{"chatgpt", checkChatGPT(parent, client, cfg.Timeout)}
	}()
	go func() {
		results <- auxiliaryResult{"google", checkGoogle(parent, client, cfg.Timeout)}
	}()

	var blackbox, chatGPT, google checkResult
	for index := 0; index < 3; index++ {
		item := <-results
		switch item.name {
		case "blackbox":
			blackbox = item.value
		case "chatgpt":
			chatGPT = item.value
		case "google":
			google = item.value
		}
		notifyProgress(progress, 60+(index+1)*10, "正在汇总检测结果")
	}
	if err := parent.Err(); err != nil {
		return report{}, err
	}

	assessment, reasons := assess(intel.Data.Security, blackbox)
	result := report{
		GeneratedAt:       time.Now().UTC(),
		Version:           version,
		ProxyHost:         cfg.ProxyHost,
		ProxyPort:         cfg.ProxyPort,
		ProxyProtocol:     usedProtocol,
		LatencyMS:         latency.Milliseconds(),
		Intel:             intel.Data,
		Blackbox:          blackbox,
		ChatGPT:           chatGPT,
		Google:            google,
		Assessment:        assessment,
		AssessmentReasons: reasons,
	}
	notifyProgress(progress, 100, "检测完成")
	return result, nil
}

func connectAndFetchIntel(parent context.Context, cfg config, progress progressFunc) (*http.Client, intelResponse, string, time.Duration, error) {
	requestedProtocol := configConnectionProtocol(cfg)
	protocols := []string{requestedProtocol}
	if requestedProtocol == protocolAuto {
		protocols = []string{protocolHTTP, protocolSOCKS5}
	}

	errorsByProtocol := make([]string, 0, len(protocols))
	for index, candidate := range protocols {
		if err := parent.Err(); err != nil {
			return nil, intelResponse{}, "", 0, err
		}
		notifyProgress(progress, 10+index*15, "正在验证连接方式："+protocolDisplayName(candidate))
		client, err := newConnectionClient(cfg, candidate)
		if err != nil {
			errorsByProtocol = append(errorsByProtocol, protocolDisplayName(candidate)+": "+err.Error())
			continue
		}

		attemptTimeout := cfg.Timeout
		if requestedProtocol == protocolAuto && attemptTimeout > 8 {
			attemptTimeout = 8
		}
		ctx, cancel := context.WithTimeout(parent, time.Duration(attemptTimeout)*time.Second)
		start := time.Now()
		intel, fetchErr := fetchIntel(ctx, client)
		latency := time.Since(start)
		cancel()
		if fetchErr == nil {
			notifyProgress(progress, 40, "已确认连接方式："+protocolDisplayName(candidate))
			return client, intel, candidate, latency, nil
		}
		client.CloseIdleConnections()
		if errors.Is(fetchErr, context.Canceled) && parent.Err() != nil {
			return nil, intelResponse{}, "", 0, parent.Err()
		}
		errorsByProtocol = append(errorsByProtocol, protocolDisplayName(candidate)+": "+sanitize(fetchErr.Error()))
	}

	return nil, intelResponse{}, "", 0, errors.New(strings.Join(errorsByProtocol, "; "))
}

func newConnectionClient(cfg config, protocol string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = time.Duration(cfg.Timeout) * time.Second
	transport.TLSHandshakeTimeout = time.Duration(cfg.Timeout) * time.Second

	switch normalizeProtocol(protocol) {
	case protocolDirect:
		// Proxy remains nil so direct checks also ignore HTTP_PROXY/HTTPS_PROXY.
	case protocolHTTP:
		proxyAddress := net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))
		proxyURL, err := url.Parse("http://" + proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case protocolSOCKS5:
		proxyAddress := net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))
		baseDialer := &net.Dialer{
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyAddress, nil, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if contextDialer, ok := dialer.(xproxy.ContextDialer); ok {
				return contextDialer.DialContext(ctx, network, address)
			}
			return dialer.Dial(network, address)
		}
	default:
		return nil, fmt.Errorf("unsupported connection protocol %q", protocol)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

func notifyProgress(progress progressFunc, percent int, message string) {
	if progress != nil {
		progress(percent, message)
	}
}

func protocolDisplayName(protocol string) string {
	switch normalizeProtocol(protocol) {
	case protocolDirect:
		return "本机直连"
	case protocolHTTP:
		return "HTTP / Mixed"
	case protocolSOCKS5:
		return "SOCKS5"
	default:
		return "自动识别"
	}
}

func fetchIntel(ctx context.Context, client *http.Client) (intelResponse, error) {
	body, status, err := get(ctx, client, intelEndpoint)
	if err != nil {
		return intelResponse{}, err
	}
	if status != http.StatusOK {
		return intelResponse{}, fmt.Errorf("whatismyip.ai returned HTTP %d", status)
	}
	var response intelResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return intelResponse{}, fmt.Errorf("decode IP intelligence response: %w", err)
	}
	if !response.Success || net.ParseIP(response.Data.IP) == nil {
		return intelResponse{}, errors.New("IP intelligence response did not contain a valid public IP")
	}
	return response, nil
}

func checkBlackbox(parent context.Context, client *http.Client, ip string, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Second)
	defer cancel()
	body, status, err := get(ctx, client, blackboxEndpoint+url.PathEscape(ip))
	if err != nil {
		return unavailable(err)
	}
	if status != http.StatusOK {
		return unavailable(fmt.Errorf("HTTP %d", status))
	}
	value := strings.TrimSpace(string(body))
	switch value {
	case "Y":
		return checkResult{Available: true, Value: "block"}
	case "N":
		return checkResult{Available: true, Value: "allow"}
	default:
		return unavailable(fmt.Errorf("unexpected response %q", value))
	}
}

func checkChatGPT(parent context.Context, client *http.Client, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Second)
	defer cancel()
	body, status, err := get(ctx, client, chatGPTEndpoint)
	if err != nil {
		return unavailable(err)
	}
	if status != http.StatusOK {
		return unavailable(fmt.Errorf("HTTP %d", status))
	}
	fields := parseKeyValues(string(body))
	location := fields["loc"]
	if location == "" {
		location = "unknown"
	}
	return checkResult{Available: true, Value: location}
}

func checkGoogle(parent context.Context, client *http.Client, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeout)*time.Second)
	defer cancel()
	_, status, err := get(ctx, client, googleEndpoint)
	if err != nil {
		return unavailable(err)
	}
	if status != http.StatusNoContent {
		return unavailable(fmt.Errorf("HTTP %d", status))
	}
	return checkResult{Available: true, Value: "reachable"}
}

func get(ctx context.Context, client *http.Client, endpoint string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("User-Agent", "ProxyIPCheck/"+version)
	request.Header.Set("Accept", "application/json,text/plain,*/*")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return body, response.StatusCode, nil
}

func parseKeyValues(value string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(value, "\n") {
		key, item, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			result[key] = item
		}
	}
	return result
}

func assess(security securityData, blackbox checkResult) (string, []string) {
	risk := riskPercent(security.Score)
	reasons := make([]string, 0, 6)
	high := security.IsBlacklisted || security.IsTor || risk >= 70
	medium := security.IsVPN || security.IsProxy || security.IsHosting || risk >= 30

	if security.IsBlacklisted {
		reasons = append(reasons, "primary source reports blacklist membership")
	}
	if security.IsTor {
		reasons = append(reasons, "Tor exit detected")
	}
	if security.IsVPN || security.IsProxy {
		reasons = append(reasons, "VPN or proxy signal detected")
	}
	if security.IsHosting {
		reasons = append(reasons, "hosting/datacenter signal detected")
	}
	if blackbox.Available && strings.HasPrefix(blackbox.Value, "block") {
		medium = true
		reasons = append(reasons, "independent source recommends blocking")
	}
	if risk >= 30 {
		reasons = append(reasons, fmt.Sprintf("risk score is %.0f/100", risk))
	}

	if high {
		return "high risk / 高风险", reasons
	}
	if medium {
		return "review needed / 建议复核", reasons
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no major risk signal was returned")
	}
	return "low risk / 低风险", reasons
}

func riskPercent(score float64) float64 {
	if score >= 0 && score <= 1 {
		score *= 100
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func printReport(value report) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "\n===== IP Quality Report / IP 质量报告 =====")
	fmt.Fprintf(writer, "Exit IP / 出口 IP:\t%s (%s)\n", sanitize(value.Intel.IP), sanitize(value.Intel.Version))
	fmt.Fprintf(writer, "Latency / 查询延迟:\t%d ms\n", value.LatencyMS)
	fmt.Fprintf(writer, "Location / 地区:\t%s, %s, %s (%s)\n", sanitize(value.Intel.Location.City), sanitize(value.Intel.Location.Region), sanitize(value.Intel.Location.Country), sanitize(value.Intel.Location.CountryCode))
	fmt.Fprintf(writer, "Timezone / 时区:\t%s\n", sanitize(value.Intel.Location.Timezone))
	fmt.Fprintf(writer, "ASN:\t%s\n", sanitize(value.Intel.Network.ASN))
	fmt.Fprintf(writer, "ISP:\t%s\n", sanitize(value.Intel.Network.ISP))
	fmt.Fprintf(writer, "Organization / 组织:\t%s\n", sanitize(value.Intel.Network.Organization))
	fmt.Fprintf(writer, "Connection type / 线路类型:\t%s\n", sanitize(value.Intel.Network.ConnectionType))
	fmt.Fprintf(writer, "Risk score / 风险分数:\t%.0f/100\n", riskPercent(value.Intel.Security.Score))
	fmt.Fprintf(writer, "VPN:\t%s\n", yesNo(value.Intel.Security.IsVPN))
	fmt.Fprintf(writer, "Proxy database / 代理标记:\t%s\n", yesNo(value.Intel.Security.IsProxy))
	fmt.Fprintf(writer, "Tor:\t%s\n", yesNo(value.Intel.Security.IsTor))
	fmt.Fprintf(writer, "Hosting / 机房标记:\t%s\n", yesNo(value.Intel.Security.IsHosting))
	fmt.Fprintf(writer, "Blacklist / 黑名单:\t%s\n", yesNo(value.Intel.Security.IsBlacklisted))
	fmt.Fprintf(writer, "Independent reputation / 独立信誉:\t%s\n", displayCheck(value.Blackbox))
	fmt.Fprintf(writer, "ChatGPT:\t%s\n", displayCheck(value.ChatGPT))
	fmt.Fprintf(writer, "Google:\t%s\n", displayCheck(value.Google))
	fmt.Fprintf(writer, "Summary / 综合判断:\t%s\n", value.Assessment)
	for _, reason := range value.AssessmentReasons {
		fmt.Fprintf(writer, "Reason / 原因:\t%s\n", reason)
	}
	writer.Flush()
	fmt.Println("\nNote: results are signals from public services, not an absolute guarantee.")
}

func sanitize(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
}

func yesNo(value bool) string {
	if value {
		return "yes / 是"
	}
	return "no / 否"
}

func displayCheck(value checkResult) string {
	if value.Available {
		return sanitize(value.Value)
	}
	return "unavailable / 不可用 (" + sanitize(value.Error) + ")"
}

func unavailable(err error) checkResult {
	return checkResult{Available: false, Error: err.Error()}
}

func pauseIfNeeded(enabled, disabledByFlag bool) {
	if !enabled || disabledByFlag {
		return
	}
	fmt.Print("\nPress Enter to exit / 按回车键退出...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
