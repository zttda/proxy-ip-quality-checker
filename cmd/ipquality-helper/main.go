package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("expected helper command: bc, dig, dnsbl, nc, ss, or time"))
	}

	var err error
	switch os.Args[1] {
	case "bc":
		err = runBC(os.Args[2:], os.Stdin, os.Stdout)
	case "dig":
		err = runDig(os.Args[2:], os.Stdout)
	case "dnsbl":
		err = runDNSBL(os.Args[2:], os.Stdin, os.Stdout)
	case "nc":
		err = runNC(os.Args[2:], os.Stdin, os.Stdout)
	case "ss":
		return
	case "time":
		runChinaTime(os.Stdout)
		return
	default:
		err = fmt.Errorf("unsupported helper command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func runChinaTime(output io.Writer) {
	chinaStandardTime := time.FixedZone("CST", 8*60*60)
	fmt.Fprintln(output, time.Now().In(chinaStandardTime).Format("2006-01-02 15:04:05 CST"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func runBC(args []string, input io.Reader, output io.Writer) error {
	for _, arg := range args {
		if arg == "--version" || arg == "-v" {
			fmt.Fprintln(output, "ipquality-helper bc 1.0")
			return nil
		}
	}
	content, err := io.ReadAll(io.LimitReader(input, 4096))
	if err != nil {
		return err
	}
	expression := strings.TrimSpace(string(content))
	if separator := strings.LastIndex(expression, ";"); separator >= 0 {
		expression = strings.TrimSpace(expression[separator+1:])
	}
	value, boolean, err := evaluateSimpleExpression(expression)
	if err != nil {
		return err
	}
	if boolean != nil {
		if *boolean {
			fmt.Fprintln(output, "1")
		} else {
			fmt.Fprintln(output, "0")
		}
		return nil
	}
	linear := false
	for _, arg := range args {
		linear = linear || arg == "-l"
	}
	if linear {
		fmt.Fprintf(output, "%.10f\n", value)
		return nil
	}
	if math.Abs(value-math.Round(value)) < 1e-9 {
		fmt.Fprintf(output, "%.0f\n", value)
	} else {
		fmt.Fprintln(output, strconv.FormatFloat(value, 'f', 10, 64))
	}
	return nil
}

func evaluateSimpleExpression(expression string) (float64, *bool, error) {
	fields := strings.Fields(expression)
	if len(fields) == 0 {
		return 0, nil, errors.New("empty expression")
	}
	for index, field := range fields {
		switch field {
		case "<", ">", "<=", ">=", "==", "!=":
			left, err := evaluateArithmetic(fields[:index])
			if err != nil {
				return 0, nil, err
			}
			right, err := evaluateArithmetic(fields[index+1:])
			if err != nil {
				return 0, nil, err
			}
			result := false
			switch field {
			case "<":
				result = left < right
			case ">":
				result = left > right
			case "<=":
				result = left <= right
			case ">=":
				result = left >= right
			case "==":
				result = left == right
			case "!=":
				result = left != right
			}
			return 0, &result, nil
		}
	}
	value, err := evaluateArithmetic(fields)
	return value, nil, err
}

func evaluateArithmetic(fields []string) (float64, error) {
	if len(fields) == 0 || len(fields)%2 == 0 {
		return 0, errors.New("invalid arithmetic expression")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse number %q: %w", fields[0], err)
	}
	for index := 1; index < len(fields); index += 2 {
		next, err := strconv.ParseFloat(fields[index+1], 64)
		if err != nil {
			return 0, fmt.Errorf("parse number %q: %w", fields[index+1], err)
		}
		switch fields[index] {
		case "+":
			value += next
		case "-":
			value -= next
		case "*":
			value *= next
		case "/":
			if next == 0 {
				return 0, errors.New("division by zero")
			}
			value /= next
		default:
			return 0, fmt.Errorf("unsupported operator %q", fields[index])
		}
	}
	return value, nil
}

func runDig(args []string, output io.Writer) error {
	for _, arg := range args {
		if arg == "-v" || arg == "-V" || arg == "--version" {
			fmt.Fprintln(output, "ipquality-helper dig 1.0")
			return nil
		}
	}
	short := false
	recordType := "A"
	name := ""
	for _, arg := range args {
		upper := strings.ToUpper(arg)
		switch {
		case arg == "+short":
			short = true
		case upper == "A" || upper == "AAAA" || upper == "MX":
			recordType = upper
		case strings.HasPrefix(arg, "+") || strings.HasPrefix(arg, "-"):
		default:
			name = arg
		}
	}
	if name == "" {
		return errors.New("dig requires a hostname")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make([]string, 0, 4)
	switch recordType {
	case "MX":
		records, err := net.DefaultResolver.LookupMX(ctx, name)
		if err == nil {
			for _, record := range records {
				results = append(results, fmt.Sprintf("%d %s", record.Pref, record.Host))
			}
		}
	case "AAAA":
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip6", name)
		if err == nil {
			for _, address := range addresses {
				results = append(results, address.String())
			}
		}
	default:
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
		if err == nil {
			for _, address := range addresses {
				results = append(results, address.String())
			}
		}
	}
	if short {
		for _, result := range results {
			fmt.Fprintln(output, result)
		}
		return nil
	}
	fmt.Fprintf(output, ";; flags: qr rd ra; QUERY: 1, ANSWER: %d\n", len(results))
	for _, result := range results {
		fmt.Fprintln(output, result)
	}
	return nil
}

type dnsLookupFunc func(context.Context, string) ([]net.IP, error)

func runDNSBL(args []string, input io.Reader, output io.Writer) error {
	return runDNSBLWithLookup(args, input, output, func(ctx context.Context, name string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip4", name)
	})
}

func runDNSBLWithLookup(args []string, input io.Reader, output io.Writer, lookup dnsLookupFunc) error {
	if len(args) < 1 {
		return errors.New("dnsbl requires a reversed IPv4 address")
	}
	parallel := 32
	if len(args) > 1 {
		if value, err := strconv.Atoi(args[1]); err == nil && value >= 1 && value <= 100 {
			parallel = value
		}
	}
	scanner := bufio.NewScanner(input)
	domains := make([]string, 0, 512)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	type dnsblResult int
	const (
		dnsblClean dnsblResult = iota
		dnsblMarked
		dnsblBlacklisted
	)
	jobs := make(chan string)
	results := make(chan dnsblResult, len(domains))
	for worker := 0; worker < parallel; worker++ {
		go func() {
			for domain := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				addresses, err := lookup(ctx, args[0]+"."+domain)
				cancel()
				if err != nil || len(addresses) == 0 {
					results <- dnsblClean
					continue
				}
				classification := dnsblMarked
				for _, address := range addresses {
					if address.String() == "127.0.0.2" {
						classification = dnsblBlacklisted
						break
					}
				}
				results <- classification
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, domain := range domains {
			jobs <- domain
		}
	}()
	clean, marked, blacklisted := 0, 0, 0
	for range domains {
		switch <-results {
		case dnsblClean:
			clean++
		case dnsblMarked:
			marked++
		case dnsblBlacklisted:
			blacklisted++
		}
	}
	fmt.Fprintf(output, "%d %d %d %d\n", len(domains), clean, marked, blacklisted)
	return nil
}

type ncOptions struct {
	host       string
	port       string
	sourceIP   string
	sourcePort int
	timeout    time.Duration
}

func runNC(args []string, input io.Reader, output io.Writer) error {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(output, "ipquality-helper nc [-s source] [-p port] [-w seconds] host port")
			return nil
		}
	}
	options, err := parseNCOptions(args)
	if err != nil {
		return err
	}
	connection, err := dialTarget(options)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(options.timeout))
	payload, err := io.ReadAll(io.LimitReader(input, 64<<10))
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := connection.Write(payload); err != nil {
			return err
		}
	}
	_, err = io.Copy(output, connection)
	if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		return nil
	}
	return err
}

func parseNCOptions(args []string) (ncOptions, error) {
	options := ncOptions{timeout: 5 * time.Second}
	positionals := make([]string, 0, 2)
	for index := 0; index < len(args); index++ {
		arg := args[index]
		nextValue := func() (string, error) {
			if index+1 >= len(args) {
				return "", fmt.Errorf("missing value after %s", arg)
			}
			index++
			return args[index], nil
		}
		switch {
		case arg == "-s":
			value, err := nextValue()
			if err != nil {
				return options, err
			}
			options.sourceIP = value
		case strings.HasPrefix(arg, "-s") && len(arg) > 2:
			options.sourceIP = arg[2:]
		case arg == "-p":
			value, err := nextValue()
			if err != nil {
				return options, err
			}
			options.sourcePort, err = strconv.Atoi(value)
			if err != nil {
				return options, err
			}
		case strings.HasPrefix(arg, "-p") && len(arg) > 2:
			options.sourcePort, _ = strconv.Atoi(arg[2:])
		case arg == "-w":
			value, err := nextValue()
			if err != nil {
				return options, err
			}
			seconds, err := strconv.Atoi(value)
			if err != nil {
				return options, err
			}
			options.timeout = time.Duration(seconds) * time.Second
		case strings.HasPrefix(arg, "-w") && len(arg) > 2:
			seconds, err := strconv.Atoi(arg[2:])
			if err != nil {
				return options, err
			}
			options.timeout = time.Duration(seconds) * time.Second
		case strings.HasPrefix(arg, "-"):
		default:
			positionals = append(positionals, arg)
		}
	}
	if len(positionals) < 2 {
		return options, errors.New("nc requires host and port")
	}
	options.host = positionals[len(positionals)-2]
	options.port = positionals[len(positionals)-1]
	return options, nil
}

func dialTarget(options ncOptions) (net.Conn, error) {
	target := net.JoinHostPort(strings.TrimSuffix(options.host, "."), options.port)
	proxyValue := strings.TrimSpace(os.Getenv("IPQUALITY_PROXY"))
	if proxyValue == "" {
		dialer := &net.Dialer{Timeout: options.timeout}
		if address := net.ParseIP(options.sourceIP); address != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: address, Port: options.sourcePort}
		}
		return dialer.Dial("tcp", target)
	}
	proxyURL, err := url.Parse(proxyValue)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			auth = &xproxy.Auth{User: proxyURL.User.Username(), Password: password}
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, &net.Dialer{Timeout: options.timeout})
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", target)
	case "http", "https":
		return dialHTTPProxy(proxyURL, target, options.timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}

func dialHTTPProxy(proxyURL *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	proxyAddress := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil {
		port := "80"
		if strings.EqualFold(proxyURL.Scheme, "https") {
			port = "443"
		}
		proxyAddress = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	connection, err := net.DialTimeout("tcp", proxyAddress, timeout)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConnection.Handshake(); err != nil {
			connection.Close()
			return nil, err
		}
		connection = tlsConnection
	}
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Connection: Keep-Alive\r\n"
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		request += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	request += "\r\n"
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(connection, request); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		connection.Close()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		connection.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %s", response.Status)
	}
	_ = connection.SetDeadline(time.Time{})
	return &bufferedConnection{Conn: connection, reader: reader}, nil
}

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConnection) Read(buffer []byte) (int, error) {
	return connection.reader.Read(buffer)
}
