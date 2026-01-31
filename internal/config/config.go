package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type ResponseConfig struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       any               `json:"body"`
}

type RuleConfig struct {
	Name        string         `json:"name"`
	Method      string         `json:"method"`
	URLPattern  string         `json:"url_pattern"`
	BodyPattern string         `json:"body_pattern"`
	Response    ResponseConfig `json:"response"`
}

type FileConfig struct {
	Rules []RuleConfig `json:"rules"`
}

// LoadDir loads all *.json config files from the given directory and merges
// their rules in alphabetical file order. If the directory does not exist,
// it returns an empty slice (passthrough mode).
func LoadDir(dir string) ([]RuleConfig, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	pattern := filepath.Join(dir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("globbing config files: %w", err)
	}

	sort.Strings(files)

	var allRules []RuleConfig
	for _, f := range files {
		rules, err := loadFile(f)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", f, err)
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func loadFile(path string) ([]RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var fc FileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	return fc.Rules, nil
}

// WriteSampleConfig creates the config directory and writes an example config file.
func WriteSampleConfig(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	sample := FileConfig{
		Rules: []RuleConfig{
			{
				Name:       "example_get",
				Method:     "GET",
				URLPattern: "/api/example",
				Response: ResponseConfig{
					StatusCode: 200,
					Headers:    map[string]string{"Content-Type": "application/json"},
					Body:       map[string]any{"message": "Hello from goproxy!", "mocked": true},
				},
			},
			{
				Name:       "example_post",
				Method:     "POST",
				URLPattern: "/api/example",
				Response: ResponseConfig{
					StatusCode: 201,
					Headers:    map[string]string{"Content-Type": "application/json"},
					Body:       map[string]any{"id": 1, "created": true},
				},
			},
		},
	}

	data, err := json.MarshalIndent(sample, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "example.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}

	return os.WriteFile(path, data, 0644)
}
