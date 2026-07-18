package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunChinaTimeUsesUTCPlusEight(t *testing.T) {
	var output bytes.Buffer
	runChinaTime(&output)
	chinaStandardTime := time.FixedZone("CST", 8*60*60)
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05 MST", strings.TrimSpace(output.String()), chinaStandardTime)
	if err != nil {
		t.Fatalf("runChinaTime() returned invalid time: %v", err)
	}
	if delta := time.Since(parsed.UTC()); delta < -2*time.Second || delta > 2*time.Second {
		t.Fatalf("runChinaTime() time delta = %v", delta)
	}
}

func TestEvaluateSimpleExpression(t *testing.T) {
	value, boolean, err := evaluateSimpleExpression("0.25 * 60")
	if err != nil || boolean != nil || value != 15 {
		t.Fatalf("evaluateSimpleExpression() = %v, %v, %v", value, boolean, err)
	}
	_, boolean, err = evaluateSimpleExpression("-1 < 0")
	if err != nil || boolean == nil || !*boolean {
		t.Fatalf("comparison = %v, %v", boolean, err)
	}
}

func TestRunDNSBLCountsResults(t *testing.T) {
	lookup := func(_ context.Context, name string) ([]net.IP, error) {
		switch {
		case strings.HasSuffix(name, ".blocked.test"):
			return []net.IP{net.ParseIP("127.0.0.2")}, nil
		case strings.HasSuffix(name, ".marked.test"):
			return []net.IP{net.ParseIP("127.0.0.3")}, nil
		default:
			return nil, &net.DNSError{IsNotFound: true}
		}
	}
	var output bytes.Buffer
	err := runDNSBLWithLookup([]string{"4.3.2.1", "2"}, strings.NewReader("clean.test\nblocked.test\nmarked.test\n"), &output, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != "3 1 1 1" {
		t.Fatalf("runDNSBLWithLookup() = %q", got)
	}
}

func TestRunBCLinearOutputKeepsDecimalPoint(t *testing.T) {
	var output bytes.Buffer
	if err := runBC([]string{"-l"}, strings.NewReader("0.5 * 60"), &output); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != "30.0000000000" {
		t.Fatalf("runBC() = %q", got)
	}
}

func TestParseNCOptions(t *testing.T) {
	options, err := parseNCOptions([]string{"-s", "203.0.113.1", "-w4", "mail.example", "25"})
	if err != nil {
		t.Fatal(err)
	}
	if options.host != "mail.example" || options.port != "25" || options.timeout.Seconds() != 4 {
		t.Fatalf("parseNCOptions() = %#v", options)
	}
}
