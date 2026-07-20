//go:build windows && gui

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type metricTableModel struct {
	walk.TableModelBase
	rows []metricRow
}

func (model *metricTableModel) RowCount() int {
	return len(model.rows)
}

func (model *metricTableModel) Value(row, column int) interface{} {
	item := model.rows[row]
	switch column {
	case 0:
		return item.Name
	case 1:
		return item.Value
	case 2:
		return item.Status
	default:
		return ""
	}
}

func (model *metricTableModel) setRows(rows []metricRow) {
	model.rows = rows
	model.PublishRowsReset()
}

type appUI struct {
	appDir        string
	configPath    string
	model         *metricTableModel
	boldFont      *walk.Font
	terminalFont  *walk.Font
	terminalBrush *walk.SolidColorBrush

	window           *walk.MainWindow
	hostEdit         *walk.LineEdit
	portEdit         *walk.NumberEdit
	timeoutEdit      *walk.NumberEdit
	autoRadio        *walk.RadioButton
	httpRadio        *walk.RadioButton
	socksRadio       *walk.RadioButton
	directCheck      *walk.CheckBox
	quickModeRadio   *walk.RadioButton
	fullModeRadio    *walk.RadioButton
	startButton      *walk.PushButton
	cancelButton     *walk.PushButton
	openLastButton   *walk.PushButton
	openFolderButton *walk.PushButton
	copyButton       *walk.PushButton
	port7897Button   *walk.PushButton
	port7890Button   *walk.PushButton
	port1080Button   *walk.PushButton
	progressBar      *walk.ProgressBar
	statusLabel      *walk.Label
	ipLabel          *walk.Label
	riskLabel        *walk.Label
	protocolLabel    *walk.Label
	resultTabs       *walk.TabWidget
	metricTable      *walk.TableView
	originalHost     *walk.Composite
	originalWebView  *walk.WebView
	originalFallback *walk.TextEdit
	logEdit          *walk.TextEdit
	statusBar        *walk.StatusBarItem

	running             bool
	loading             bool
	cancel              context.CancelFunc
	latestResult        *report
	latestQuickFiles    quickReportFiles
	latestIPQuality     *ipqualityResult
	latestFullFiles     ipqualityReportFiles
	displayedResultMode string
	closed              atomic.Bool
}

func main() {
	runtime.LockOSThread()
	initConsole()
	ui, err := newAppUI()
	if err != nil {
		walk.MsgBox(nil, "Proxy IP 质量检测", err.Error(), walk.MsgBoxIconError)
		return
	}
	defer ui.dispose()
	ui.window.Run()
}

func newAppUI() (*appUI, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("无法定位程序目录：%w", err)
	}
	appDir := filepath.Dir(executable)
	configPath := filepath.Join(appDir, "config.json")
	cfg, _, configErr := loadConfig(configPath)
	if configErr != nil {
		cfg = defaultConfig()
	}

	boldFont, err := walk.NewFont("Microsoft YaHei UI", 9, walk.FontBold)
	if err != nil {
		return nil, fmt.Errorf("无法创建界面字体：%w", err)
	}
	ui := &appUI{
		appDir:     appDir,
		configPath: configPath,
		model:      &metricTableModel{rows: placeholderMetrics()},
		boldFont:   boldFont,
	}

	windowDefinition := MainWindow{
		AssignTo:   &ui.window,
		Title:      "Proxy IP 质量检测",
		Size:       Size{Width: 1100, Height: 810},
		MinSize:    Size{Width: 940, Height: 700},
		Font:       Font{Family: "Microsoft YaHei UI", PointSize: 9},
		Background: SolidColorBrush{Color: walk.RGB(244, 246, 248)},
		Layout:     VBox{Margins: Margins{Left: 18, Top: 16, Right: 18, Bottom: 14}, Spacing: 10},
		StatusBarItems: []StatusBarItem{
			{AssignTo: &ui.statusBar, Text: "免安装版 · 检测结果仅供参考", Width: 260},
			{Text: "结果自动保存在程序目录", Width: 260},
		},
		Children: []Widget{
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     HBox{Margins: Margins{Left: 14, Top: 10, Right: 12, Bottom: 10}, Spacing: 8},
				Children: []Widget{
					Label{Text: "Proxy IP Inspector", Font: Font{Family: "Microsoft YaHei UI", PointSize: 14, Bold: true}, TextColor: walk.RGB(23, 33, 43)},
					HSpacer{},
					PushButton{AssignTo: &ui.copyButton, Text: "复制摘要", MinSize: Size{Width: 88}, Enabled: false, ToolTipText: "复制本次检测的关键结果", OnClicked: ui.copySummary},
					PushButton{AssignTo: &ui.openLastButton, Text: "打开上次报告", MinSize: Size{Width: 112}, ToolTipText: "打开同目录下保存的 HTML 报告", OnClicked: ui.openLastReport},
					PushButton{AssignTo: &ui.openFolderButton, Text: "打开目录", MinSize: Size{Width: 88}, OnClicked: ui.openAppFolder},
				},
			},
			GroupBox{
				Title:      "连接设置",
				Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     VBox{Margins: Margins{Left: 12, Top: 10, Right: 12, Bottom: 12}, Spacing: 8},
				Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
						Label{Text: "地址", TextColor: walk.RGB(90, 101, 112)},
						LineEdit{AssignTo: &ui.hostEdit, StretchFactor: 1, MinSize: Size{Width: 220}, ToolTipText: "本地代理监听地址"},
						Label{Text: "端口", TextColor: walk.RGB(90, 101, 112)},
						NumberEdit{AssignTo: &ui.portEdit, MinSize: Size{Width: 90}, MaxSize: Size{Width: 100}, Decimals: 0, MinValue: 1, MaxValue: 65535, Increment: 1, SpinButtonsVisible: true},
						Label{Text: "超时", TextColor: walk.RGB(90, 101, 112)},
						NumberEdit{AssignTo: &ui.timeoutEdit, MinSize: Size{Width: 82}, MaxSize: Size{Width: 92}, Decimals: 0, MinValue: 5, MaxValue: 120, Increment: 5, SpinButtonsVisible: true, Suffix: " 秒"},
						HSpacer{},
						PushButton{AssignTo: &ui.startButton, Text: "开始检测", MinSize: Size{Width: 122, Height: 30}, ToolTipText: "检测当前公网出口 IP 和质量", OnClicked: ui.startCheck},
						PushButton{AssignTo: &ui.cancelButton, Text: "取消", MinSize: Size{Width: 72, Height: 30}, Enabled: false, OnClicked: ui.cancelCheck},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
						Label{Text: "协议", TextColor: walk.RGB(90, 101, 112)},
						RadioButtonGroup{Buttons: []RadioButton{
							{AssignTo: &ui.autoRadio, Text: "自动识别", Value: protocolAuto, MinSize: Size{Width: 100}, ToolTipText: "先验证 HTTP / Mixed，不通时再验证 SOCKS5"},
							{AssignTo: &ui.httpRadio, Text: "HTTP / Mixed", Value: protocolHTTP, MinSize: Size{Width: 120}},
							{AssignTo: &ui.socksRadio, Text: "SOCKS5", Value: protocolSOCKS5, MinSize: Size{Width: 90}},
						}},
						HSpacer{},
						Label{Text: "常用端口", TextColor: walk.RGB(90, 101, 112)},
						PushButton{AssignTo: &ui.port7897Button, Text: "7897", MinSize: Size{Width: 62}, OnClicked: func() { _ = ui.portEdit.SetValue(7897) }},
						PushButton{AssignTo: &ui.port7890Button, Text: "7890", MinSize: Size{Width: 62}, OnClicked: func() { _ = ui.portEdit.SetValue(7890) }},
						PushButton{AssignTo: &ui.port1080Button, Text: "1080", MinSize: Size{Width: 62}, OnClicked: func() { _ = ui.portEdit.SetValue(1080) }},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
						Label{Text: "检测模式", TextColor: walk.RGB(90, 101, 112)},
						RadioButtonGroup{Buttons: []RadioButton{
							{AssignTo: &ui.quickModeRadio, Text: "快速检测", Value: checkModeQuick, MinSize: Size{Width: 110}, ToolTipText: "约数秒完成，使用本工具内置的检测源", OnClicked: ui.modeSelectionChanged},
							{AssignTo: &ui.fullModeRadio, Text: "IPQuality 完整检测", Value: checkModeFull, MinSize: Size{Width: 170}, ToolTipText: "运行固定版本的 xykt/IPQuality 全部模块，通常需要数分钟", OnClicked: ui.modeSelectionChanged},
						}},
						HSpacer{},
						CheckBox{AssignTo: &ui.directCheck, Text: "本机直连（不使用代理）", MinSize: Size{Width: 210}, ToolTipText: "绕过代理，检测当前电脑的公网出口 IP", OnCheckedChanged: ui.directModeChanged},
					}},
				},
			},
			Composite{
				MinSize: Size{Height: 82},
				MaxSize: Size{Height: 92},
				Layout:  HBox{MarginsZero: true, Spacing: 10},
				Children: []Widget{
					GroupBox{Title: "出口 IP", StretchFactor: 1, AlwaysConsumeSpace: true, MinSize: Size{Width: 280}, Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)}, Layout: VBox{Margins: Margins{Left: 12, Top: 9, Right: 12, Bottom: 10}}, Children: []Widget{
						Label{AssignTo: &ui.ipLabel, Text: "尚未检测", Font: Font{Family: "Segoe UI", PointSize: 13, Bold: true}, TextColor: walk.RGB(23, 33, 43), EllipsisMode: EllipsisEnd},
					}},
					GroupBox{Title: "综合判断", StretchFactor: 1, AlwaysConsumeSpace: true, MinSize: Size{Width: 280}, Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)}, Layout: VBox{Margins: Margins{Left: 12, Top: 9, Right: 12, Bottom: 10}}, Children: []Widget{
						Label{AssignTo: &ui.riskLabel, Text: "等待检测", Font: Font{Family: "Microsoft YaHei UI", PointSize: 13, Bold: true}, TextColor: walk.RGB(102, 113, 124)},
					}},
					GroupBox{Title: "连接方式", StretchFactor: 1, AlwaysConsumeSpace: true, MinSize: Size{Width: 280}, Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)}, Layout: VBox{Margins: Margins{Left: 12, Top: 9, Right: 12, Bottom: 10}}, Children: []Widget{
						Label{AssignTo: &ui.protocolLabel, Text: "-", Font: Font{Family: "Segoe UI", PointSize: 13, Bold: true}, TextColor: walk.RGB(40, 95, 158)},
					}},
				},
			},
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     Grid{Columns: 5, Margins: Margins{Left: 12, Top: 9, Right: 12, Bottom: 9}, Spacing: 9},
				Children: []Widget{
					Label{Text: "检测状态", Row: 0, Column: 0, TextColor: walk.RGB(90, 101, 112)},
					ProgressBar{AssignTo: &ui.progressBar, Row: 0, Column: 1, ColumnSpan: 2, MinValue: 0, MaxValue: 100, Value: 0, MinSize: Size{Height: 18}},
					Label{AssignTo: &ui.statusLabel, Row: 0, Column: 3, ColumnSpan: 2, Text: "就绪", TextColor: walk.RGB(40, 95, 158), EllipsisMode: EllipsisEnd},
				},
			},
			TabWidget{
				AssignTo:           &ui.resultTabs,
				StretchFactor:      1,
				ContentMarginsZero: true,
				Pages: []TabPage{
					{
						Title:  "指标概览",
						Layout: VBox{MarginsZero: true},
						Children: []Widget{
							TableView{
								AssignTo:                    &ui.metricTable,
								StretchFactor:               1,
								Model:                       ui.model,
								AlternatingRowBG:            true,
								LastColumnStretched:         false,
								NotSortableByHeaderClick:    true,
								SelectionHiddenWithoutFocus: true,
								CustomRowHeight:             27,
								Columns: []TableViewColumn{
									{Title: "指标", Width: 230},
									{Title: "检测结果", Width: 650},
									{Title: "状态", Width: 100, Alignment: AlignCenter},
								},
								StyleCell: ui.styleMetricCell,
							},
						},
					},
					{
						Title:  "IPQuality 原始报告",
						Layout: VBox{MarginsZero: true},
						Children: []Widget{
							Composite{AssignTo: &ui.originalHost, Layout: VBox{MarginsZero: true}},
						},
					},
				},
			},
			Composite{
				MinSize: Size{Height: 98},
				MaxSize: Size{Height: 106},
				Layout:  VBox{MarginsZero: true, Spacing: 5},
				Children: []Widget{
					Label{Text: "运行记录", TextColor: walk.RGB(90, 101, 112)},
					TextEdit{AssignTo: &ui.logEdit, ReadOnly: true, VScroll: true, MinSize: Size{Height: 74}, MaxSize: Size{Height: 84}, Background: SolidColorBrush{Color: walk.RGB(250, 251, 252)}, TextColor: walk.RGB(69, 78, 87)},
				},
			},
		},
	}

	if err := windowDefinition.Create(); err != nil {
		boldFont.Dispose()
		return nil, fmt.Errorf("无法创建主窗口：%w", err)
	}
	ui.window.Closing().Attach(func(_ *bool, _ walk.CloseReason) {
		ui.closed.Store(true)
		if ui.cancel != nil {
			ui.cancel()
		}
	})
	ui.initOriginalReportViewer()
	ui.applyConfig(cfg)
	ui.loadLastResults(cfg)
	if configErr != nil {
		ui.appendLog("配置文件无效，已恢复默认值：" + configErr.Error())
	}
	return ui, nil
}

func (ui *appUI) dispose() {
	if ui.terminalBrush != nil {
		ui.terminalBrush.Dispose()
	}
	if ui.terminalFont != nil {
		ui.terminalFont.Dispose()
	}
	if ui.boldFont != nil {
		ui.boldFont.Dispose()
	}
}

func (ui *appUI) initOriginalReportViewer() {
	viewer, err := walk.NewWebView(ui.originalHost)
	if err == nil {
		viewer.SetShortcutsEnabled(true)
		viewer.SetNativeContextMenuEnabled(false)
		ui.originalWebView = viewer
		return
	}

	fallback, fallbackErr := walk.NewTextEdit(ui.originalHost)
	if fallbackErr != nil {
		ui.appendLog("无法创建原始报告视图：" + fallbackErr.Error())
		return
	}
	_ = fallback.SetReadOnly(true)
	fallback.SetTextColor(walk.RGB(204, 204, 204))
	if brush, brushErr := walk.NewSolidColorBrush(walk.RGB(12, 12, 12)); brushErr == nil {
		ui.terminalBrush = brush
		fallback.SetBackground(brush)
	}
	if font, fontErr := walk.NewFont("Consolas", 10, 0); fontErr == nil {
		ui.terminalFont = font
		fallback.SetFont(font)
	}
	ui.originalFallback = fallback
	ui.appendLog("系统彩色报告组件不可用，已使用深色文本回退：" + err.Error())
}

func (ui *appUI) showOriginalIPQualityReport(result ipqualityResult) {
	path := ui.latestFullFiles.OriginalHTML
	if path == "" {
		if files, err := ipqualityReportFilesForIP(ui.appDir, result.Document.Head.IP); err == nil {
			path = files.OriginalHTML
		}
	}
	if path == "" {
		ui.showOriginalReportMessage(result.PlainText)
		return
	}
	if !fileExists(path) {
		if err := os.WriteFile(path, renderTerminalDocument(ipqualityTerminalSource(result)), 0o600); err != nil {
			ui.appendLog("生成原始彩色报告失败：" + err.Error())
		}
	}
	ui.showOriginalReportFile(path, result.PlainText)
}

func (ui *appUI) showOriginalReportMessage(message string) {
	directory := filepath.Join(ui.appDir, "runtime", "tmp")
	path := filepath.Join(directory, "ipquality-original-view.html")
	if err := os.MkdirAll(directory, 0o755); err == nil {
		if writeErr := os.WriteFile(path, renderTerminalDocument(message), 0o600); writeErr == nil {
			ui.showOriginalReportFile(path, message)
			return
		}
	}
	if ui.originalFallback != nil {
		_ = ui.originalFallback.SetText(windowsMultilineText(message))
	}
}

func (ui *appUI) showOriginalReportFile(path, fallbackText string) {
	if ui.originalWebView != nil && fileExists(path) {
		address, err := localFileURL(path)
		if err == nil {
			address += fmt.Sprintf("?view=%d", time.Now().UnixNano())
			if err := ui.originalWebView.SetURL(address); err == nil {
				return
			}
		}
	}
	if ui.originalFallback != nil {
		_ = ui.originalFallback.SetText(windowsMultilineText(fallbackText))
	}
}

func localFileURL(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	urlPath := filepath.ToSlash(absolute)
	if filepath.VolumeName(absolute) != "" && !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	return (&url.URL{Scheme: "file", Path: urlPath}).String(), nil
}

func (ui *appUI) applyConfig(cfg config) {
	ui.loading = true
	_ = ui.hostEdit.SetText(cfg.ProxyHost)
	_ = ui.portEdit.SetValue(float64(cfg.ProxyPort))
	_ = ui.timeoutEdit.SetValue(float64(cfg.Timeout))
	ui.directCheck.SetChecked(cfg.Direct)
	switch normalizeProtocol(cfg.Protocol) {
	case protocolHTTP:
		ui.httpRadio.SetChecked(true)
	case protocolSOCKS5:
		ui.socksRadio.SetChecked(true)
	default:
		ui.autoRadio.SetChecked(true)
	}
	if normalizeCheckMode(cfg.CheckMode) == checkModeFull {
		ui.fullModeRadio.SetChecked(true)
	} else {
		ui.quickModeRadio.SetChecked(true)
	}
	ui.loading = false
	ui.updateConnectionControls()
}

func (ui *appUI) selectedConfig() config {
	protocol := protocolAuto
	if ui.httpRadio.Checked() {
		protocol = protocolHTTP
	} else if ui.socksRadio.Checked() {
		protocol = protocolSOCKS5
	}
	mode := checkModeQuick
	if ui.fullModeRadio.Checked() {
		mode = checkModeFull
	}
	return config{
		ProxyHost:   strings.TrimSpace(ui.hostEdit.Text()),
		ProxyPort:   int(ui.portEdit.Value()),
		Protocol:    protocol,
		Direct:      ui.directCheck.Checked(),
		CheckMode:   mode,
		Timeout:     int(ui.timeoutEdit.Value()),
		PauseOnExit: false,
	}
}

func (ui *appUI) directModeChanged() {
	if ui.loading {
		return
	}
	ui.updateConnectionControls()
}

func (ui *appUI) updateConnectionControls() {
	enabled := !ui.running && (ui.directCheck == nil || !ui.directCheck.Checked())
	ui.hostEdit.SetEnabled(enabled)
	ui.portEdit.SetEnabled(enabled)
	ui.autoRadio.SetEnabled(enabled)
	ui.httpRadio.SetEnabled(enabled)
	ui.socksRadio.SetEnabled(enabled)
	ui.port7897Button.SetEnabled(enabled)
	ui.port7890Button.SetEnabled(enabled)
	ui.port1080Button.SetEnabled(enabled)
}

func (ui *appUI) selectedMode() string {
	if ui.fullModeRadio != nil && ui.fullModeRadio.Checked() {
		return checkModeFull
	}
	return checkModeQuick
}

func (ui *appUI) modeSelectionChanged() {
	if ui.loading || ui.running || ui.quickModeRadio == nil || ui.fullModeRadio == nil {
		return
	}
	mode := ui.selectedMode()
	if mode == ui.displayedResultMode {
		return
	}
	ui.displayStoredResult(mode)
	ui.updateReportButton()
}

func (ui *appUI) startCheck() {
	if ui.running {
		return
	}
	cfg := ui.selectedConfig()
	if err := validateConfig(cfg); err != nil {
		walk.MsgBox(ui.window, "连接设置有误", configErrorChinese(err), walk.MsgBoxIconWarning)
		return
	}
	if err := saveConfig(ui.configPath, cfg); err != nil {
		walk.MsgBox(ui.window, "无法保存配置", err.Error(), walk.MsgBoxIconWarning)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	ui.cancel = cancel
	ui.setRunning(true)
	ui.copyButton.SetEnabled(false)
	ui.progressBar.SetValue(0)
	ui.ipLabel.SetText("检测中...")
	ui.riskLabel.SetText("正在分析")
	ui.riskLabel.SetTextColor(walk.RGB(40, 95, 158))
	ui.protocolLabel.SetText(protocolDisplayName(configConnectionProtocol(cfg)))
	ui.appendLog(fmt.Sprintf("开始%s：%s", checkModeDisplayName(cfg.CheckMode), configConnectionSummary(cfg)))

	if normalizeCheckMode(cfg.CheckMode) == checkModeFull {
		previous := ui.latestIPQuality
		go ui.runFullCheck(ctx, cfg, previous)
		return
	}
	previous := ui.latestResult
	go ui.runQuickCheck(ctx, cfg, previous)
}

func (ui *appUI) runQuickCheck(ctx context.Context, cfg config, previous *report) {
	result, checkErr := performCheck(ctx, cfg, ui.progressCallback())
	var savedFiles quickReportFiles
	if checkErr == nil {
		savedFiles, checkErr = saveLatestSuccess(ui.appDir, cfg, result)
	}
	if checkErr != nil && !errors.Is(checkErr, context.Canceled) {
		if saveErr := saveLatestFailure(ui.appDir, cfg, checkErr); saveErr != nil {
			checkErr = fmt.Errorf("%v；保存失败记录时又发生错误：%w", checkErr, saveErr)
		}
	}
	ui.synchronize(func() {
		ui.finishRun()
		if errors.Is(checkErr, context.Canceled) {
			ui.restoreQuickAfterCancel(previous)
			ui.showCanceled()
			return
		}
		if checkErr != nil {
			ui.showFailure(checkErr, checkModeQuick)
			return
		}
		ui.showResult(result, savedFiles)
	})
}

func (ui *appUI) runFullCheck(ctx context.Context, cfg config, previous *ipqualityResult) {
	result, checkErr := performIPQualityCheck(ctx, ui.appDir, cfg, ui.progressCallback())
	var savedFiles ipqualityReportFiles
	if checkErr == nil {
		savedFiles, checkErr = saveLatestIPQuality(ui.appDir, result)
	}
	if checkErr != nil && !errors.Is(checkErr, context.Canceled) {
		if saveErr := saveIPQualityFailure(ui.appDir, checkErr); saveErr != nil {
			checkErr = fmt.Errorf("%v；保存失败记录时又发生错误：%w", checkErr, saveErr)
		}
	}
	ui.synchronize(func() {
		ui.finishRun()
		if errors.Is(checkErr, context.Canceled) {
			ui.restoreFullAfterCancel(previous)
			ui.showCanceled()
			return
		}
		if checkErr != nil {
			ui.showFailure(checkErr, checkModeFull)
			return
		}
		ui.showIPQualityResult(result, savedFiles)
	})
}

func (ui *appUI) progressCallback() progressFunc {
	return func(percent int, message string) {
		ui.synchronize(func() {
			ui.progressBar.SetValue(percent)
			ui.statusLabel.SetText(message)
			ui.statusBar.SetText(message)
		})
	}
}

func (ui *appUI) finishRun() {
	ui.setRunning(false)
	ui.cancel = nil
}

func (ui *appUI) showCanceled() {
	ui.statusLabel.SetText("检测已取消")
	ui.statusBar.SetText("检测已取消")
	ui.appendLog("检测已取消，保留上一次完成的结果")
}

func (ui *appUI) cancelCheck() {
	if ui.cancel != nil {
		ui.statusLabel.SetText("正在取消...")
		ui.cancel()
	}
}

func (ui *appUI) setRunning(running bool) {
	ui.running = running
	ui.timeoutEdit.SetEnabled(!running)
	ui.directCheck.SetEnabled(!running)
	ui.quickModeRadio.SetEnabled(!running)
	ui.fullModeRadio.SetEnabled(!running)
	ui.startButton.SetEnabled(!running)
	ui.cancelButton.SetEnabled(running)
	ui.updateConnectionControls()
	ui.updateReportButton()
}

func (ui *appUI) showResult(result report, files quickReportFiles) {
	ui.latestQuickFiles = files
	ui.applyResult(result)
	_ = ui.resultTabs.SetCurrentIndex(0)
	label, _ := assessmentLabel(result.Assessment)
	ui.progressBar.SetValue(100)
	ui.statusLabel.SetText("检测完成，结果已保存")
	ui.statusBar.SetText("检测完成 · 结果已保存")
	ui.openLastButton.SetEnabled(true)
	ui.appendLog(fmt.Sprintf("检测完成：出口 %s，%s，已保存 %s", result.Intel.IP, label, filepath.Base(files.HTML)))
}

func (ui *appUI) applyResult(result report) {
	ui.latestResult = &result
	ui.displayedResultMode = checkModeQuick
	ui.model.setRows(metricsForReport(result))
	_ = ui.metricTable.Invalidate()
	ui.showOriginalReportMessage("快速检测不生成 IPQuality 原项目报告。")
	ui.ipLabel.SetText(result.Intel.IP)
	label, state := assessmentLabel(result.Assessment)
	ui.riskLabel.SetText(fmt.Sprintf("%s · %.0f/100", label, riskPercent(result.Intel.Security.Score)))
	ui.riskLabel.SetTextColor(colorForState(state))
	ui.protocolLabel.SetText(protocolDisplayName(result.ProxyProtocol))
	ui.copyButton.SetEnabled(true)
}

func (ui *appUI) showIPQualityResult(result ipqualityResult, files ipqualityReportFiles) {
	ui.latestFullFiles = files
	ui.applyIPQualityResult(result)
	_ = ui.resultTabs.SetCurrentIndex(1)
	label, _ := assessmentLabel(result.Assessment)
	ui.progressBar.SetValue(100)
	ui.statusLabel.SetText("完整检测完成，原始报告已保存")
	ui.statusBar.SetText("IPQuality 完整检测完成 · 结果已保存")
	ui.updateReportButton()
	ui.appendLog(fmt.Sprintf("完整检测完成：出口 %s，%s，已保存 %s", result.Document.Head.IP, label, filepath.Base(files.HTML)))
}

func (ui *appUI) applyIPQualityResult(result ipqualityResult) {
	ui.latestIPQuality = &result
	ui.displayedResultMode = checkModeFull
	ui.model.setRows(metricsForIPQuality(result))
	_ = ui.metricTable.Invalidate()
	ui.showOriginalIPQualityReport(result)
	ui.ipLabel.SetText(result.Document.Head.IP)
	label, state := assessmentLabel(result.Assessment)
	if score, _, ok := maxIPQualityScore(result.Document.Score); ok {
		ui.riskLabel.SetText(fmt.Sprintf("%s · 最高 %.0f/100", label, score))
	} else {
		ui.riskLabel.SetText(label + " · 多数据库")
	}
	ui.riskLabel.SetTextColor(colorForState(state))
	ui.protocolLabel.SetText(protocolDisplayName(result.ProxyProtocol))
	ui.copyButton.SetEnabled(true)
}

func (ui *appUI) showFailure(checkErr error, mode string) {
	ui.displayedResultMode = normalizeCheckMode(mode)
	ui.copyButton.SetEnabled(false)
	ui.model.setRows([]metricRow{{Name: "检测失败", Value: sanitize(checkErr.Error()), Status: "失败", State: stateBad}})
	_ = ui.metricTable.Invalidate()
	ui.showOriginalReportMessage("本次检测未完成，没有新的 IPQuality 原始报告。")
	_ = ui.resultTabs.SetCurrentIndex(0)
	ui.progressBar.SetValue(0)
	ui.ipLabel.SetText("检测失败")
	ui.riskLabel.SetText("未得出结论")
	ui.riskLabel.SetTextColor(walk.RGB(180, 35, 24))
	ui.protocolLabel.SetText("-")
	ui.statusLabel.SetText("失败：" + sanitize(checkErr.Error()))
	ui.statusBar.SetText("检测失败")
	ui.updateReportButton()
	ui.appendLog("检测失败：" + sanitize(checkErr.Error()))
}

func (ui *appUI) loadLastResults(cfg config) {
	session, quickFiles, err := loadLatestQuickSession(ui.appDir)
	if err == nil && session.Success && session.Result != nil {
		ui.latestResult = session.Result
		ui.latestQuickFiles = quickFiles
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		ui.appendLog("读取快速检测结果失败：" + err.Error())
	}

	fullResult, fullFiles, fullErr := loadLatestIPQuality(ui.appDir, cfg)
	if fullErr == nil {
		ui.latestIPQuality = &fullResult
		ui.latestFullFiles = fullFiles
	} else if !errors.Is(fullErr, os.ErrNotExist) {
		ui.appendLog("读取 IPQuality 结果失败：" + fullErr.Error())
	}

	mode := normalizeCheckMode(cfg.CheckMode)
	ui.displayStoredResult(mode)
	if (mode == checkModeQuick && ui.latestResult != nil) || (mode == checkModeFull && ui.latestIPQuality != nil) {
		ui.progressBar.SetValue(100)
		ui.statusLabel.SetText("已加载上次检测结果")
		ui.statusBar.SetText("已加载上次检测结果")
		ui.appendLog("已加载上次完成的" + checkModeDisplayName(mode))
	}
	ui.updateReportButton()
}

func (ui *appUI) restoreQuickAfterCancel(previous *report) {
	if previous != nil {
		ui.applyResult(*previous)
		ui.progressBar.SetValue(100)
		return
	}
	ui.displayEmptyState(checkModeQuick)
}

func (ui *appUI) restoreFullAfterCancel(previous *ipqualityResult) {
	if previous != nil {
		ui.applyIPQualityResult(*previous)
		ui.progressBar.SetValue(100)
		return
	}
	ui.displayEmptyState(checkModeFull)
}

func (ui *appUI) displayStoredResult(mode string) {
	mode = normalizeCheckMode(mode)
	if mode == checkModeFull {
		if ui.latestIPQuality != nil {
			ui.applyIPQualityResult(*ui.latestIPQuality)
			ui.progressBar.SetValue(100)
			ui.statusLabel.SetText("已显示上次 IPQuality 完整检测")
			ui.statusBar.SetText("已显示上次 IPQuality 完整检测")
			return
		}
		ui.displayEmptyState(checkModeFull)
		return
	}
	if ui.latestResult != nil {
		ui.applyResult(*ui.latestResult)
		ui.progressBar.SetValue(100)
		ui.statusLabel.SetText("已显示上次快速检测")
		ui.statusBar.SetText("已显示上次快速检测")
		return
	}
	ui.displayEmptyState(checkModeQuick)
}

func (ui *appUI) displayEmptyState(mode string) {
	ui.displayedResultMode = normalizeCheckMode(mode)
	if ui.displayedResultMode == checkModeFull {
		ui.model.setRows(placeholderIPQualityMetrics())
	} else {
		ui.model.setRows(placeholderMetrics())
	}
	_ = ui.metricTable.Invalidate()
	if ui.displayedResultMode == checkModeFull {
		ui.showOriginalReportMessage("尚未运行 IPQuality 完整检测。")
	} else {
		ui.showOriginalReportMessage("快速检测不生成 IPQuality 原项目报告。")
	}
	_ = ui.resultTabs.SetCurrentIndex(0)
	ui.progressBar.SetValue(0)
	ui.ipLabel.SetText("尚未检测")
	ui.riskLabel.SetText("等待检测")
	ui.riskLabel.SetTextColor(walk.RGB(102, 113, 124))
	ui.protocolLabel.SetText("-")
	ui.statusLabel.SetText("就绪")
	ui.statusBar.SetText("就绪")
	ui.copyButton.SetEnabled(false)
}

func windowsMultilineText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func (ui *appUI) synchronize(action func()) {
	if ui.closed.Load() {
		return
	}
	ui.window.Synchronize(func() {
		if !ui.closed.Load() {
			action()
		}
	})
}

func (ui *appUI) copySummary() {
	if ui.displayedResultMode == checkModeFull {
		ui.copyIPQualitySummary()
		return
	}
	if ui.latestResult == nil {
		return
	}
	result := *ui.latestResult
	label, _ := assessmentLabel(result.Assessment)
	text := fmt.Sprintf("出口 IP：%s\r\n地区：%s\r\n连接方式：%s\r\n风险：%s（%.0f/100）\r\nISP：%s\r\nASN：%s",
		sanitize(result.Intel.IP),
		formatLocation(result.Intel.Location),
		protocolDisplayName(result.ProxyProtocol),
		label,
		riskPercent(result.Intel.Security.Score),
		sanitize(result.Intel.Network.ISP),
		sanitize(result.Intel.Network.ASN),
	)
	if err := walk.Clipboard().SetText(text); err != nil {
		walk.MsgBox(ui.window, "复制失败", err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.appendLog("检测摘要已复制到剪贴板")
}

func (ui *appUI) copyIPQualitySummary() {
	if ui.latestIPQuality == nil {
		return
	}
	result := *ui.latestIPQuality
	label, _ := assessmentLabel(result.Assessment)
	risk := "未返回"
	if score, source, ok := maxIPQualityScore(result.Document.Score); ok {
		risk = fmt.Sprintf("%.0f/100（%s）", score, source)
	}
	text := fmt.Sprintf("出口 IP：%s\r\n地区：%s\r\n连接方式：%s\r\n综合判断：%s\r\n最高风险分数：%s\r\n组织：%s\r\nASN：%s\r\n上游：xykt/IPQuality %s",
		ipqualityValue(result.Document.Head.IP),
		ipqualityLocation(result.Document.Info),
		protocolDisplayName(result.ProxyProtocol),
		label,
		risk,
		ipqualityValue(result.Document.Info.Organization),
		prefixASN(result.Document.Info.ASN),
		ipqualityValue(result.Document.Head.Version),
	)
	if err := walk.Clipboard().SetText(text); err != nil {
		walk.MsgBox(ui.window, "复制失败", err.Error(), walk.MsgBoxIconError)
		return
	}
	ui.appendLog("IPQuality 检测摘要已复制到剪贴板")
}

func (ui *appUI) openLastReport() {
	path := ui.activeReportPath()
	if !fileExists(path) {
		walk.MsgBox(ui.window, "没有报告", "尚未找到保存的检测报告。", walk.MsgBoxIconInformation)
		return
	}
	if err := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", path).Start(); err != nil {
		walk.MsgBox(ui.window, "无法打开报告", err.Error(), walk.MsgBoxIconError)
	}
}

func (ui *appUI) activeReportPath() string {
	if ui.displayedResultMode == checkModeFull {
		return ui.latestFullFiles.HTML
	}
	return ui.latestQuickFiles.HTML
}

func (ui *appUI) updateReportButton() {
	if ui.openLastButton == nil {
		return
	}
	ui.openLastButton.SetEnabled(!ui.running && fileExists(ui.activeReportPath()))
}

func (ui *appUI) openAppFolder() {
	if err := exec.Command("explorer.exe", ui.appDir).Start(); err != nil {
		walk.MsgBox(ui.window, "无法打开目录", err.Error(), walk.MsgBoxIconError)
	}
}

func (ui *appUI) appendLog(message string) {
	line := time.Now().Format("15:04:05") + "  " + sanitize(message)
	current := strings.TrimSpace(ui.logEdit.Text())
	if current != "" {
		current += "\r\n"
	}
	ui.logEdit.SetText(current + line)
}

func (ui *appUI) styleMetricCell(style *walk.CellStyle) {
	row := style.Row()
	if row < 0 || row >= len(ui.model.rows) {
		return
	}
	if style.Col() == 2 {
		style.TextColor = colorForState(ui.model.rows[row].State)
		style.Font = ui.boldFont
	}
}

func placeholderMetrics() []metricRow {
	names := []string{
		"出口 IP", "连接方式", "查询延迟", "地区", "时区", "ASN", "ISP", "组织", "线路类型",
		"风险分数", "VPN 标记", "代理数据库标记", "Tor 出口", "Hosting / 机房", "黑名单", "独立信誉", "ChatGPT", "Google",
	}
	rows := make([]metricRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, metricRow{Name: name, Value: "-", Status: "待检测", State: stateInfo})
	}
	return rows
}

func placeholderIPQualityMetrics() []metricRow {
	names := []string{
		"出口 IP", "连接方式", "ASN", "网络组织", "地理位置", "注册地区", "时区", "IP 类型",
		"用途类型数据库", "公司类型数据库", "风险分数数据库", "国家代码一致性", "代理标记", "Tor 标记",
		"VPN 标记", "机房 / 服务器标记", "滥用记录", "机器人流量标记", "流媒体与 AI 解锁", "邮件服务", "DNSBL 黑名单",
	}
	rows := make([]metricRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, metricRow{Name: name, Value: "-", Status: "待检测", State: stateInfo})
	}
	return rows
}

func checkModeDisplayName(mode string) string {
	if normalizeCheckMode(mode) == checkModeFull {
		return "IPQuality 完整检测"
	}
	return "快速检测"
}

func colorForState(state metricState) walk.Color {
	switch state {
	case stateGood:
		return walk.RGB(19, 122, 90)
	case stateWarning:
		return walk.RGB(154, 99, 0)
	case stateBad:
		return walk.RGB(180, 35, 24)
	default:
		return walk.RGB(40, 95, 158)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func configErrorChinese(err error) string {
	switch err.Error() {
	case "proxyHost must be an IPv4 address or hostname":
		return "代理地址必须是 IPv4 地址或合法主机名。"
	case "proxyPort must be between 1 and 65535":
		return "代理端口必须在 1 到 65535 之间。"
	case "timeoutSeconds must be between 5 and 120":
		return "超时时间必须在 5 到 120 秒之间。"
	case "proxyProtocol must be auto, http, or socks5":
		return "请选择自动识别、HTTP / Mixed 或 SOCKS5。"
	case "checkMode must be quick or ipquality":
		return "请选择快速检测或 IPQuality 完整检测。"
	default:
		return err.Error()
	}
}
