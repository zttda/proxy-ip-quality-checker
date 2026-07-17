package main

import "testing"

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  config
		wantErr bool
	}{
		{name: "valid", config: config{ProxyHost: "127.0.0.1", ProxyPort: 7897, Timeout: 20}},
		{name: "valid hostname", config: config{ProxyHost: "localhost", ProxyPort: 8080, Timeout: 10}},
		{name: "invalid host", config: config{ProxyHost: "127.0.0.1/path", ProxyPort: 7897, Timeout: 20}, wantErr: true},
		{name: "invalid port", config: config{ProxyHost: "127.0.0.1", ProxyPort: 70000, Timeout: 20}, wantErr: true},
		{name: "short timeout", config: config{ProxyHost: "127.0.0.1", ProxyPort: 7897, Timeout: 1}, wantErr: true},
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
	assessment, reasons := assess(securityData{}, checkResult{Available: true, Value: "block recommended / 建议拦截"})
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
