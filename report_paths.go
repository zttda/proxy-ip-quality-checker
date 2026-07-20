package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	quickErrorHTMLName = "ipcheck-last-error.html"
	quickErrorJSONName = "ipcheck-last-error.json"
	ipqualityErrorName = "ipquality-last-error.txt"
)

type quickReportFiles struct {
	HTML string
	JSON string
}

type ipqualityReportFiles struct {
	HTML         string
	OriginalHTML string
	JSON         string
	Text         string
	Metadata     string
}

type reportFilePair struct {
	source string
	target string
}

func reportIPToken(exitIP string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(exitIP))
	if parsed == nil {
		return "", fmt.Errorf("invalid report exit IP %q", exitIP)
	}
	return strings.ReplaceAll(parsed.String(), ":", "-"), nil
}

func quickReportFilesForIP(directory, exitIP string) (quickReportFiles, error) {
	token, err := reportIPToken(exitIP)
	if err != nil {
		return quickReportFiles{}, err
	}
	prefix := filepath.Join(directory, "ipcheck-"+token+"-result")
	return quickReportFiles{HTML: prefix + ".html", JSON: prefix + ".json"}, nil
}

func quickReportFilesFromJSON(jsonPath string) quickReportFiles {
	prefix := strings.TrimSuffix(jsonPath, ".json")
	return quickReportFiles{HTML: prefix + ".html", JSON: jsonPath}
}

func ipqualityReportFilesForIP(directory, exitIP string) (ipqualityReportFiles, error) {
	token, err := reportIPToken(exitIP)
	if err != nil {
		return ipqualityReportFiles{}, err
	}
	prefix := filepath.Join(directory, "ipquality-"+token)
	return ipqualityReportFiles{
		HTML:         prefix + "-result.html",
		OriginalHTML: prefix + "-original.html",
		JSON:         prefix + "-result.json",
		Text:         prefix + "-result.txt",
		Metadata:     prefix + "-result.meta.json",
	}, nil
}

func ipqualityReportFilesFromJSON(jsonPath string) ipqualityReportFiles {
	prefix := strings.TrimSuffix(jsonPath, "-result.json")
	return ipqualityReportFiles{
		HTML:         prefix + "-result.html",
		OriginalHTML: prefix + "-original.html",
		JSON:         jsonPath,
		Text:         prefix + "-result.txt",
		Metadata:     prefix + "-result.meta.json",
	}
}

func reportJSONCandidates(directory, prefix, suffix string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			paths = append(paths, filepath.Join(directory, name))
		}
	}
	if len(paths) == 0 {
		return nil, os.ErrNotExist
	}
	return paths, nil
}

func migrateReportFiles(pairs []reportFilePair) error {
	type pendingWrite struct {
		path    string
		content []byte
	}
	writes := make([]pendingWrite, 0, len(pairs))
	for _, pair := range pairs {
		content, err := os.ReadFile(pair.source)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		writes = append(writes, pendingWrite{path: pair.target, content: content})
	}
	for _, write := range writes {
		if err := os.WriteFile(write.path, write.content, 0o600); err != nil {
			return err
		}
	}
	for _, pair := range pairs {
		if err := os.Remove(pair.source); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func removeReportFiles(paths ...string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
