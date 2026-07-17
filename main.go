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
)

var version = "dev"

const (
	intelEndpoint    = "https://whatismyip.ai/api/ip"
	blackboxEndpoint = "https://blackbox.ipinfo.app/api/v1/"
	chatGPTEndpoint  = "https://chatgpt.com/cdn-cgi/trace"
	googleEndpoint   = "https://www.google.com/generate_204"
	maxResponseBytes = 2 << 20
)

type config struct {
	ProxyHost   string `json:"proxyHost"`
	ProxyPort   int    `json:"proxyPort"`
	Timeout     int    `json:"timeoutSeconds"`
	SaveJSON    bool   `json:"saveJson"`
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
	LatencyMS         int64       `json:"latencyMs"`
	Intel             intelData   `json:"intel"`
	Blackbox          checkResult `json:"independentReputation"`
	ChatGPT           checkResult `json:"chatGPT"`
	Google            checkResult `json:"google"`
	Assessment        string      `json:"assessment"`
	AssessmentReasons []string    `json:"assessmentReasons"`
}

func main() {
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
		Timeout:     20,
		SaveJSON:    false,
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
	if net.ParseIP(cfg.ProxyHost) == nil && !validHostname(cfg.ProxyHost) {
		return errors.New("proxyHost must be an IPv4 address or hostname")
	}
	if cfg.ProxyPort < 1 || cfg.ProxyPort > 65535 {
		return errors.New("proxyPort must be between 1 and 65535")
	}
	if cfg.Timeout < 5 || cfg.Timeout > 120 {
		return errors.New("timeoutSeconds must be between 5 and 120")
	}
	return nil
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
	fmt.Printf("Proxy: http://%s:%d\n\n", cfg.ProxyHost, cfg.ProxyPort)

	client, err := newProxyClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	start := time.Now()
	intel, err := fetchIntel(ctx, client)
	cancel()
	latency := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: primary IP intelligence check failed: %v\n", err)
		return 1
	}

	var blackbox, chatGPT, google checkResult
	done := make(chan struct{}, 3)
	go func() {
		blackbox = checkBlackbox(client, intel.Data.IP, cfg.Timeout)
		done <- struct{}{}
	}()
	go func() {
		chatGPT = checkChatGPT(client, cfg.Timeout)
		done <- struct{}{}
	}()
	go func() {
		google = checkGoogle(client, cfg.Timeout)
		done <- struct{}{}
	}()
	for range 3 {
		<-done
	}

	assessment, reasons := assess(intel.Data.Security, blackbox)
	result := report{
		GeneratedAt:       time.Now().UTC(),
		Version:           version,
		LatencyMS:         latency.Milliseconds(),
		Intel:             intel.Data,
		Blackbox:          blackbox,
		ChatGPT:           chatGPT,
		Google:            google,
		Assessment:        assessment,
		AssessmentReasons: reasons,
	}

	printReport(result)
	if cfg.SaveJSON {
		outputPath := filepath.Join(filepath.Dir(configPath), "ipcheck-result.json")
		if err := saveReport(outputPath, result); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not save JSON report: %v\n", err)
		} else {
			fmt.Printf("\nJSON report: %s\n", outputPath)
		}
	}
	return 0
}

func newProxyClient(cfg config) (*http.Client, error) {
	proxyAddress := "http://" + net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ResponseHeaderTimeout = time.Duration(cfg.Timeout) * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout) * time.Second,
	}, nil
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

func checkBlackbox(client *http.Client, ip string, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
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
		return checkResult{Available: true, Value: "block recommended / 建议拦截"}
	case "N":
		return checkResult{Available: true, Value: "allow / 建议放行"}
	default:
		return unavailable(fmt.Errorf("unexpected response %q", value))
	}
}

func checkChatGPT(client *http.Client, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
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
		location = "unknown region"
	}
	return checkResult{Available: true, Value: "reachable, region " + location}
}

func checkGoogle(client *http.Client, timeout int) checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
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

func saveReport(path string, value report) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

func pauseIfNeeded(enabled, disabledByFlag bool) {
	if !enabled || disabledByFlag {
		return
	}
	fmt.Print("\nPress Enter to exit / 按回车键退出...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
