package main

import (
	"fmt"
	"html"
	"html/template"
	"strconv"
	"strings"
	"unicode"
)

const (
	terminalBackground = "#0c0c0c"
	terminalForeground = "#cccccc"
)

var terminalPalette = [...]string{
	"#0c0c0c", "#c50f1f", "#13a10e", "#c19c00",
	"#0037da", "#881798", "#3a96dd", "#cccccc",
	"#767676", "#e74856", "#16c60c", "#f9f1a5",
	"#3b78ff", "#b4009e", "#61d6d6", "#f2f2f2",
}

type terminalStyle struct {
	foreground string
	background string
	bold       bool
	dim        bool
	underline  bool
	inverse    bool
}

func ipqualityTerminalSource(result ipqualityResult) string {
	if strings.TrimSpace(result.TerminalText) != "" {
		return result.TerminalText
	}
	return result.PlainText
}

func renderTerminalDocument(value string) []byte {
	fragment := renderANSITerminalFragment(value)
	return []byte(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="dark">
<style>
html,body{margin:0;min-height:100%;background:#0c0c0c;color:#cccccc;letter-spacing:0}
body{overflow:auto}
pre{box-sizing:border-box;min-height:100vh;margin:0;padding:16px 18px;background:#0c0c0c;color:#cccccc;white-space:pre;font:14px/1.5 Consolas,"Cascadia Mono","Microsoft YaHei UI",monospace;tab-size:4}
::selection{background:#264f78;color:#fff}
</style>
</head>
<body><pre>` + string(fragment) + `</pre></body>
</html>`)
}

func renderANSITerminalFragment(value string) template.HTML {
	value = prepareTerminalOutput(value)

	var output strings.Builder
	style := terminalStyle{}
	spanOpen := false
	textStart := 0
	for index := 0; index < len(value); {
		if value[index] != 0x1b || index+1 >= len(value) || value[index+1] != '[' {
			index++
			continue
		}
		appendTerminalText(&output, value[textStart:index])
		end := index + 2
		for end < len(value) && (value[end] < '@' || value[end] > '~') {
			end++
		}
		if end >= len(value) {
			textStart = index + 1
			index++
			continue
		}
		if value[end] == 'm' {
			updated := applyTerminalSGR(style, value[index+2:end])
			if updated != style {
				if spanOpen {
					output.WriteString("</span>")
					spanOpen = false
				}
				style = updated
				if css := style.css(); css != "" {
					output.WriteString(`<span style="`)
					output.WriteString(css)
					output.WriteString(`">`)
					spanOpen = true
				}
			}
		}
		index = end + 1
		textStart = index
	}
	appendTerminalText(&output, value[textStart:])
	if spanOpen {
		output.WriteString("</span>")
	}
	return template.HTML(output.String())
}

func prepareTerminalOutput(value string) string {
	value = ansiOSC.ReplaceAllString(value, "")
	value = normalizeTerminalCarriageReturns(value)

	cursor := 0
	styleStart := -1
	for cursor < len(value) {
		if value[cursor] == 0x1b && cursor+1 < len(value) && value[cursor+1] == '[' {
			end := cursor + 2
			for end < len(value) && (value[end] < '@' || value[end] > '~') {
				end++
			}
			if end < len(value) {
				if value[end] == 'm' && styleStart < 0 {
					styleStart = cursor
				}
				cursor = end + 1
				continue
			}
		}
		if value[cursor] == '\n' || value[cursor] == '\t' || value[cursor] == ' ' {
			cursor++
			continue
		}
		break
	}
	if styleStart >= 0 {
		cursor = styleStart
	}
	return strings.TrimRightFunc(value[cursor:], unicode.IsSpace)
}

func normalizeTerminalCarriageReturns(value string) string {
	var output strings.Builder
	output.Grow(len(value))
	atLineStart := true
	for index := 0; index < len(value); index++ {
		if value[index] != '\r' {
			output.WriteByte(value[index])
			atLineStart = value[index] == '\n'
			continue
		}
		if index+1 < len(value) && value[index+1] == '\n' {
			output.WriteByte('\n')
			atLineStart = true
			index++
			continue
		}
		if atLineStart {
			continue
		}
		output.WriteByte('\n')
		atLineStart = true
	}
	return output.String()
}

func appendTerminalText(output *strings.Builder, value string) {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || !unicode.IsControl(character) {
			return character
		}
		return -1
	}, value)
	output.WriteString(html.EscapeString(value))
}

func applyTerminalSGR(style terminalStyle, sequence string) terminalStyle {
	parameters := parseTerminalSGR(sequence)
	for index := 0; index < len(parameters); index++ {
		parameter := parameters[index]
		switch {
		case parameter == 0:
			style = terminalStyle{}
		case parameter == 1:
			style.bold = true
		case parameter == 2:
			style.dim = true
		case parameter == 4:
			style.underline = true
		case parameter == 7:
			style.inverse = true
		case parameter == 22:
			style.bold = false
			style.dim = false
		case parameter == 24:
			style.underline = false
		case parameter == 27:
			style.inverse = false
		case parameter >= 30 && parameter <= 37:
			style.foreground = terminalPalette[parameter-30]
		case parameter >= 90 && parameter <= 97:
			style.foreground = terminalPalette[parameter-90+8]
		case parameter == 39:
			style.foreground = ""
		case parameter >= 40 && parameter <= 47:
			style.background = terminalPalette[parameter-40]
		case parameter >= 100 && parameter <= 107:
			style.background = terminalPalette[parameter-100+8]
		case parameter == 49:
			style.background = ""
		case parameter == 38 || parameter == 48:
			color, consumed, ok := extendedTerminalColor(parameters[index+1:])
			if ok {
				if parameter == 38 {
					style.foreground = color
				} else {
					style.background = color
				}
				index += consumed
			}
		}
	}
	return style
}

func parseTerminalSGR(sequence string) []int {
	if sequence == "" {
		return []int{0}
	}
	parts := strings.Split(sequence, ";")
	parameters := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			parameters = append(parameters, 0)
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		parameters = append(parameters, value)
	}
	if len(parameters) == 0 {
		return []int{0}
	}
	return parameters
}

func extendedTerminalColor(parameters []int) (color string, consumed int, ok bool) {
	if len(parameters) >= 2 && parameters[0] == 5 && parameters[1] >= 0 && parameters[1] <= 255 {
		return terminal256Color(parameters[1]), 2, true
	}
	if len(parameters) >= 4 && parameters[0] == 2 {
		red, green, blue := parameters[1], parameters[2], parameters[3]
		if red >= 0 && red <= 255 && green >= 0 && green <= 255 && blue >= 0 && blue <= 255 {
			return fmt.Sprintf("#%02x%02x%02x", red, green, blue), 4, true
		}
	}
	return "", 0, false
}

func terminal256Color(index int) string {
	if index < len(terminalPalette) {
		return terminalPalette[index]
	}
	if index >= 232 {
		level := 8 + (index-232)*10
		return fmt.Sprintf("#%02x%02x%02x", level, level, level)
	}
	index -= 16
	levels := [...]int{0, 95, 135, 175, 215, 255}
	red := levels[index/36]
	green := levels[(index/6)%6]
	blue := levels[index%6]
	return fmt.Sprintf("#%02x%02x%02x", red, green, blue)
}

func (style terminalStyle) css() string {
	foreground := style.foreground
	background := style.background
	if style.inverse {
		if foreground == "" {
			foreground = terminalForeground
		}
		if background == "" {
			background = terminalBackground
		}
		foreground, background = background, foreground
	}
	properties := make([]string, 0, 5)
	if foreground != "" {
		properties = append(properties, "color:"+foreground)
	}
	if background != "" {
		properties = append(properties, "background-color:"+background)
	}
	if style.bold {
		properties = append(properties, "font-weight:700")
	}
	if style.dim {
		properties = append(properties, "opacity:.72")
	}
	if style.underline {
		properties = append(properties, "text-decoration:underline")
	}
	return strings.Join(properties, ";")
}
