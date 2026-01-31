package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dougbarrett/goproxy/internal/config"
	"github.com/dougbarrett/goproxy/internal/proxy"
	"github.com/dougbarrett/goproxy/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		runInit()
	case "help", "--help", "-h":
		printUsage()
	default:
		runProxy(os.Args[1:])
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `goproxy - HTTP mock proxy wrapper

Usage:
  goproxy <command> [args...]    Wrap a command with the mock proxy
  goproxy init                   Create .goproxy/ with a sample config

Examples:
  goproxy go run ./cmd/app
  goproxy ./mybin --flag1 --flag2
  goproxy init

The proxy loads rules from all .json files in the .goproxy/ directory.
If no .goproxy/ directory exists, the proxy runs in passthrough mode.
`)
}

func runInit() {
	dir := filepath.Join(".", ".goproxy")
	if err := config.WriteSampleConfig(dir); err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}
	fmt.Printf("Created %s with example config\n", dir)
	fmt.Println("Edit .goproxy/example.json to add your proxy rules.")
}

func runProxy(cmdArgs []string) {
	configDir := filepath.Join(".", ".goproxy")

	// Load config
	rules, err := config.LoadDir(configDir)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if len(rules) == 0 {
		log.Println("No proxy rules loaded — running in passthrough mode")
	} else {
		log.Printf("Loaded %d proxy rules", len(rules))
	}

	// Find a free port
	port, err := freePort()
	if err != nil {
		log.Fatalf("Failed to find free port: %v", err)
	}

	// Generate unique instance UUID
	uuid := generateUUID()

	// Create proxy server
	srv, err := proxy.NewServer(uuid, configDir, rules)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	httpServer := &http.Server{Addr: addr, Handler: srv}

	// Start proxy in background
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	fmt.Printf("\n  goproxy running on %s\n", proxyURL)
	fmt.Printf("  Instance ID: %s\n\n", uuid)
	fmt.Printf("  Admin endpoints:\n")
	fmt.Printf("    GET  %s/__proxy__/%s/logs    - View captured requests\n", proxyURL, uuid)
	fmt.Printf("    POST %s/__proxy__/%s/clear   - Clear request logs\n", proxyURL, uuid)
	fmt.Printf("    POST %s/__proxy__/%s/reload  - Reload config\n", proxyURL, uuid)
	fmt.Printf("    GET  %s/__proxy__/%s/health  - Health check\n\n", proxyURL, uuid)
	fmt.Printf("  Running: %v\n\n", cmdArgs)

	// Start the wrapped command
	r := runner.New(proxyURL, cmdArgs)
	if err := r.Start(); err != nil {
		log.Fatalf("Failed to start command: %v", err)
	}

	// Forward signals to child process
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		r.Signal(sig)
	}()

	// Wait for child to exit
	exitCode := r.Wait()

	// Shutdown proxy server and close log file
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
	srv.Close()

	os.Exit(exitCode)
}

// freePort asks the OS for an available TCP port.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

// generateUUID generates a UUID v4 using crypto/rand (no external deps).
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate UUID: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
