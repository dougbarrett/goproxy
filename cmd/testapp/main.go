package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	fmt.Println("=== goproxy test app ===")
	fmt.Printf("HTTP_PROXY:  %s\n", os.Getenv("HTTP_PROXY"))
	fmt.Printf("HTTPS_PROXY: %s\n\n", os.Getenv("HTTPS_PROXY"))

	// Test 1: GET request that should match a mock rule
	fmt.Println("--- Test 1: GET /api/example (should be mocked) ---")
	doRequest("GET", "http://mockserver.local/api/example", "")

	// Test 2: POST request that should match a mock rule
	fmt.Println("--- Test 2: POST /api/example (should be mocked) ---")
	doRequest("POST", "http://mockserver.local/api/example", `{"name":"test"}`)

	// Test 3: Request that won't match any rule (catch-all)
	fmt.Println("--- Test 3: GET /unknown/path (catch-all) ---")
	doRequest("GET", "http://mockserver.local/unknown/path", "")

	fmt.Println("=== tests complete ===")
}

func doRequest(method, url, body string) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		fmt.Printf("  ERROR creating request: %v\n\n", err)
		return
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  ERROR: %v\n\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("  Status: %d\n", resp.StatusCode)
	fmt.Printf("  Body:   %s\n\n", string(respBody))
}
