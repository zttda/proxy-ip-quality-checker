package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ipqualityDocument struct {
	Head   ipqualityHead                   `json:"Head"`
	Info   ipqualityInfo                   `json:"Info"`
	Type   ipqualityType                   `json:"Type"`
	Score  map[string]any                  `json:"Score"`
	Factor map[string]map[string]any       `json:"Factor"`
	Media  map[string]ipqualityMediaResult `json:"Media"`
	Mail   map[string]any                  `json:"Mail"`
}

type ipqualityHead struct {
	IP      string `json:"IP"`
	Command string `json:"Command"`
	GitHub  string `json:"GitHub"`
	Time    string `json:"Time"`
	Version string `json:"Version"`
}

type ipqualityInfo struct {
	ASN              string         `json:"ASN"`
	Organization     string         `json:"Organization"`
	Latitude         string         `json:"Latitude"`
	Longitude        string         `json:"Longitude"`
	DMS              string         `json:"DMS"`
	Map              string         `json:"Map"`
	TimeZone         string         `json:"TimeZone"`
	City             ipqualityPlace `json:"City"`
	Region           ipqualityPlace `json:"Region"`
	Continent        ipqualityPlace `json:"Continent"`
	RegisteredRegion ipqualityPlace `json:"RegisteredRegion"`
	Type             string         `json:"Type"`
}

type ipqualityPlace struct {
	Code         string `json:"Code"`
	Name         string `json:"Name"`
	PostalCode   string `json:"PostalCode"`
	SubCode      string `json:"SubCode"`
	Subdivisions string `json:"Subdivisions"`
}

type ipqualityType struct {
	Usage   map[string]any `json:"Usage"`
	Company map[string]any `json:"Company"`
}

type ipqualityMediaResult struct {
	Status string `json:"Status"`
	Region string `json:"Region"`
	Type   string `json:"Type"`
}

type ipqualityResult struct {
	GeneratedAt       time.Time
	ProxyHost         string
	ProxyPort         int
	ProxyProtocol     string
	Document          ipqualityDocument
	RawJSON           []byte
	TerminalText      string
	PlainText         string
	Assessment        string
	AssessmentReasons []string
}

type ipqualityMetadata struct {
	GeneratedAt       time.Time `json:"generatedAt"`
	ProxyHost         string    `json:"proxyHost"`
	ProxyPort         int       `json:"proxyPort"`
	ProxyProtocol     string    `json:"proxyProtocol"`
	Assessment        string    `json:"assessment"`
	AssessmentReasons []string  `json:"assessmentReasons"`
}

func performIPQualityCheck(parent context.Context, appDir string, cfg config, progress progressFunc) (ipqualityResult, error) {
	if err := validateConfig(cfg); err != nil {
		return ipqualityResult{}, err
	}
	if err := validateIPQualityRuntime(appDir); err != nil {
		return ipqualityResult{}, err
	}
	if err := os.MkdirAll(filepath.Join(appDir, "runtime", "tmp"), 0o755); err != nil {
		return ipqualityResult{}, fmt.Errorf("创建内置运行时临时目录失败: %w", err)
	}

	cfg.Protocol = normalizeProtocol(cfg.Protocol)
	notifyProgress(progress, 5, "正在确认连接方式")
	client, _, usedProtocol, _, err := connectAndFetchIntel(parent, cfg, nil)
	if err != nil {
		return ipqualityResult{}, fmt.Errorf("网络连接或公网 IP 查询失败: %w", err)
	}
	client.CloseIdleConnections()
	if err := parent.Err(); err != nil {
		return ipqualityResult{}, err
	}

	proxyURL := ipqualityProxyURL(cfg, usedProtocol)
	tempFile, err := os.CreateTemp(appDir, "ipquality-run-*.json")
	if err != nil {
		return ipqualityResult{}, fmt.Errorf("创建临时结果文件失败: %w", err)
	}
	tempPath := tempFile.Name()
	if closeErr := tempFile.Close(); closeErr != nil {
		return ipqualityResult{}, closeErr
	}
	if err := os.Remove(tempPath); err != nil {
		return ipqualityResult{}, fmt.Errorf("准备临时结果文件失败: %w", err)
	}
	defer os.Remove(tempPath)

	bashPath := filepath.Join(appDir, "runtime", "usr", "bin", "bash.exe")
	outputName := filepath.Base(tempPath)
	cmd := managedCommand(parent, bashPath, ipqualityCommandArgs(usedProtocol, proxyURL, outputName)...)
	cmd.Dir = appDir
	cmd.Env = ipqualityEnvironment(appDir, proxyURL)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return ipqualityResult{}, fmt.Errorf("读取原项目运行状态失败: %w", err)
	}

	tracker := newIPQualityProgress(progress)
	tracker.update(18, "正在启动 IPQuality 完整检测")
	if err := cmd.Start(); err != nil {
		return ipqualityResult{}, fmt.Errorf("无法启动内置 IPQuality 运行环境: %w", err)
	}
	monitorDone := make(chan struct{})
	go func() {
		monitorIPQualityProgress(stderr, tracker)
		close(monitorDone)
	}()
	tickerDone := make(chan struct{})
	go tracker.tick(tickerDone)
	waitErr := cmd.Wait()
	close(tickerDone)
	<-monitorDone

	if err := parent.Err(); err != nil {
		return ipqualityResult{}, err
	}
	rawJSON, readErr := os.ReadFile(tempPath)
	if readErr != nil {
		message := cleanIPQualityText(stdout.String())
		if message == "" {
			message = sanitize(commandErrorText(waitErr))
		}
		return ipqualityResult{}, fmt.Errorf("IPQuality 未生成有效结果: %s", message)
	}
	document, err := parseIPQualityDocument(rawJSON)
	if err != nil {
		return ipqualityResult{}, fmt.Errorf("IPQuality 结果无效: %w", err)
	}

	terminalText := stdout.String()
	plainText := cleanIPQualityText(terminalText)
	if plainText == "" {
		plainText = buildIPQualityPlainText(document)
	}
	enrichIPQualityDocumentFromText(&document, plainText)
	assessment, reasons := assessIPQuality(document)
	result := ipqualityResult{
		GeneratedAt:       time.Now().UTC(),
		ProxyHost:         cfg.ProxyHost,
		ProxyPort:         cfg.ProxyPort,
		ProxyProtocol:     usedProtocol,
		Document:          document,
		RawJSON:           append([]byte(nil), rawJSON...),
		TerminalText:      terminalText,
		PlainText:         plainText,
		Assessment:        assessment,
		AssessmentReasons: reasons,
	}
	tracker.update(100, "IPQuality 完整检测完成")
	return result, nil
}

func validateIPQualityRuntime(appDir string) error {
	required := []string{
		filepath.Join("ipquality", "ip.sh"),
		filepath.Join("runtime", "usr", "bin", "bash.exe"),
		filepath.Join("runtime", "mingw64", "bin", "curl.exe"),
		filepath.Join("runtime", "tools", "jq.exe"),
		filepath.Join("runtime", "tools", "ipquality-helper.exe"),
		filepath.Join("runtime", "tools", "bc"),
		filepath.Join("runtime", "tools", "dig"),
		filepath.Join("runtime", "tools", "nc"),
		filepath.Join("runtime", "tools", "ss"),
	}
	missing := make([]string, 0)
	for _, relative := range required {
		if info, err := os.Stat(filepath.Join(appDir, relative)); err != nil || info.IsDir() {
			missing = append(missing, relative)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("完整检测组件不完整，缺少: %s", strings.Join(missing, ", "))
	}
	return nil
}

func ipqualityEnvironment(appDir, proxyURL string) []string {
	pathValue := strings.Join([]string{
		filepath.Join(appDir, "runtime", "tools"),
		filepath.Join(appDir, "runtime", "mingw64", "bin"),
		filepath.Join(appDir, "runtime", "usr", "bin"),
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
	}, string(os.PathListSeparator))
	return append(filteredEnvironment(os.Environ(), []string{
		"PATH", "IPQUALITY_EMBEDDED", "IPQUALITY_PROXY", "MSYS2_ARG_CONV_EXCL",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
		"LANG", "LC_ALL", "TERM", "CHERE_INVOKING",
	}),
		"PATH="+pathValue,
		"IPQUALITY_EMBEDDED=1",
		"IPQUALITY_PROXY="+proxyURL,
		"MSYS2_ARG_CONV_EXCL=*",
		"LANG=zh_CN.UTF-8",
		"LC_ALL=zh_CN.UTF-8",
		"TERM=xterm-256color",
		"CHERE_INVOKING=1",
	)
}

func filteredEnvironment(environment, excluded []string) []string {
	blocked := make(map[string]struct{}, len(excluded))
	for _, name := range excluded {
		blocked[strings.ToUpper(name)] = struct{}{}
	}
	result := make([]string, 0, len(environment))
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if _, skip := blocked[strings.ToUpper(name)]; found && skip {
			continue
		}
		result = append(result, item)
	}
	return result
}

func ipqualityProxyURL(cfg config, protocol string) string {
	if cfg.Direct || normalizeProtocol(protocol) == protocolDirect {
		return ""
	}
	scheme := "http"
	if normalizeProtocol(protocol) == protocolSOCKS5 {
		scheme = "socks5h"
	}
	return scheme + "://" + net.JoinHostPort(cfg.ProxyHost, strconv.Itoa(cfg.ProxyPort))
}

func ipqualityCommandArgs(protocol, proxyURL, outputName string) []string {
	args := []string{"ipquality/ip.sh", "-4", "-f", "-n", "-p", "-l", "cn"}
	if normalizeProtocol(protocol) != protocolDirect {
		args = append(args, "-x", proxyURL)
	}
	return append(args, "-o", outputName)
}

func parseIPQualityDocument(content []byte) (ipqualityDocument, error) {
	var document ipqualityDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return ipqualityDocument{}, err
	}
	if net.ParseIP(strings.TrimSpace(document.Head.IP)) == nil {
		return ipqualityDocument{}, errors.New("结果中没有有效的出口 IP")
	}
	if document.Head.GitHub != "" && !strings.EqualFold(strings.TrimSuffix(document.Head.GitHub, "/"), "https://github.com/xykt/IPQuality") {
		return ipqualityDocument{}, errors.New("结果来源不是固定的 IPQuality 项目")
	}
	return document, nil
}

type ipqualityProgress struct {
	mu       sync.Mutex
	percent  int
	message  string
	callback progressFunc
}

func newIPQualityProgress(callback progressFunc) *ipqualityProgress {
	return &ipqualityProgress{callback: callback, message: "正在运行 IPQuality 完整检测"}
}

func (tracker *ipqualityProgress) update(percent int, message string) {
	tracker.mu.Lock()
	previousPercent := tracker.percent
	previousMessage := tracker.message
	if percent < tracker.percent {
		percent = tracker.percent
	}
	if percent > 100 {
		percent = 100
	}
	tracker.percent = percent
	if strings.TrimSpace(message) != "" {
		tracker.message = message
	}
	callback := tracker.callback
	currentMessage := tracker.message
	changed := tracker.percent != previousPercent || currentMessage != previousMessage
	tracker.mu.Unlock()
	if !changed {
		return
	}
	notifyProgress(callback, percent, currentMessage)
}

func (tracker *ipqualityProgress) stage(message string) {
	tracker.mu.Lock()
	if message == tracker.message {
		tracker.mu.Unlock()
		return
	}
	percent := tracker.percent
	tracker.mu.Unlock()
	if percent < 88 {
		percent += 3
	}
	tracker.update(percent, message)
}

func (tracker *ipqualityProgress) tick(done <-chan struct{}) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			tracker.mu.Lock()
			percent := tracker.percent
			message := tracker.message
			tracker.mu.Unlock()
			if percent < 90 {
				tracker.update(percent+1, message)
			}
		}
	}
}

func monitorIPQualityProgress(reader io.Reader, tracker *ipqualityProgress) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	scanner.Split(splitCRLF)
	for scanner.Scan() {
		line := cleanIPQualityText(scanner.Text())
		if line == "" {
			continue
		}
		message := ipqualityProgressMessage(line)
		if message == "" {
			continue
		}
		tracker.stage(message)
	}
}

func splitCRLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for index, character := range data {
		if character == '\r' || character == '\n' {
			advance = index + 1
			for advance < len(data) && (data[advance] == '\r' || data[advance] == '\n') {
				advance++
			}
			return advance, data[:index], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func ipqualityProgressMessage(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "blacklist") || strings.Contains(line, "黑名单"):
		return "正在检测 DNSBL 黑名单数据库"
	case strings.Contains(lower, "media") || strings.Contains(line, "流媒体"):
		return "正在检测流媒体与 AI 服务"
	case strings.Contains(lower, "mail") || strings.Contains(line, "邮件"):
		return "正在检测邮件服务可用性"
	case strings.Contains(lower, "risk") || strings.Contains(line, "风险"):
		return "正在汇总多个风险数据库"
	case strings.Contains(lower, "checking") || strings.Contains(line, "检测") || strings.Contains(line, "查询"):
		return "IPQuality 正在查询多个公开数据库"
	default:
		return ""
	}
}

var (
	ansiCSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSC = regexp.MustCompile(`\x1b\][^\x07]*(?:\x07|\x1b\\)`)
)

func cleanIPQualityText(value string) string {
	value = ansiOSC.ReplaceAllString(value, "")
	value = ansiCSI.ReplaceAllString(value, "")
	value = normalizeTerminalCarriageReturns(value)
	value = strings.Trim(value, "\n")
	lines := strings.Split(value, "\n")
	cleaned := make([]string, 0, len(lines))
	blank := false
	for _, line := range lines {
		line = strings.TrimRightFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || (r < 32 && r != '\n')
		})
		if strings.TrimSpace(line) == "" {
			if !blank && len(cleaned) > 0 {
				cleaned = append(cleaned, "")
			}
			blank = true
			continue
		}
		cleaned = append(cleaned, line)
		blank = false
	}
	return strings.TrimSpace(strings.Join(cleaned, "\n"))
}

func commandErrorText(err error) string {
	if err == nil {
		return "原项目未返回结果"
	}
	return err.Error()
}
