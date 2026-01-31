package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/dougbarrett/goproxy/internal/config"
)

const maxBodySize = 10 * 1024 * 1024 // 10MB

type MockRule struct {
	Name        string
	Method      string
	URLPattern  *regexp.Regexp
	BodyPattern *regexp.Regexp
	Response    config.ResponseConfig
}

type RequestLog struct {
	Timestamp   time.Time           `json:"timestamp"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	MatchedRule string              `json:"matched_rule,omitempty"`
	StatusCode  int                 `json:"status_code"`
}

type Server struct {
	mu        sync.RWMutex
	rules     []MockRule
	logs      []RequestLog
	uuid      string
	configDir string
	transport *http.Transport
}

// NewServer creates a proxy server with compiled rules and a UUID for admin routes.
func NewServer(uuid string, configDir string, ruleConfigs []config.RuleConfig) (*Server, error) {
	rules, err := compileRules(ruleConfigs)
	if err != nil {
		return nil, err
	}

	s := &Server{
		rules:     rules,
		logs:      make([]RequestLog, 0),
		uuid:      uuid,
		configDir: configDir,
		transport: &http.Transport{
			Proxy: nil, // never proxy forwarded requests (avoid infinite loop)
		},
	}

	return s, nil
}

func compileRules(configs []config.RuleConfig) ([]MockRule, error) {
	rules := make([]MockRule, 0, len(configs))
	for i, rc := range configs {
		rule := MockRule{
			Name:     rc.Name,
			Method:   rc.Method,
			Response: rc.Response,
		}
		if rule.Response.StatusCode == 0 {
			rule.Response.StatusCode = 200
		}
		if rc.URLPattern != "" {
			re, err := regexp.Compile(rc.URLPattern)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): invalid url_pattern: %w", i, rc.Name, err)
			}
			rule.URLPattern = re
		}
		if rc.BodyPattern != "" {
			re, err := regexp.Compile(rc.BodyPattern)
			if err != nil {
				return nil, fmt.Errorf("rule %d (%s): invalid body_pattern: %w", i, rc.Name, err)
			}
			rule.BodyPattern = re
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Admin routes: /__proxy__/<uuid>/...
	adminPrefix := fmt.Sprintf("/__proxy__/%s/", s.uuid)
	if endpoint, found := strings.CutPrefix(r.URL.Path, adminPrefix); found {
		s.handleAdmin(w, endpoint)
		return
	}

	// HTTPS CONNECT tunneling — forward transparently
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	// Read request body for rule matching
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	fullURL := r.URL.String()
	if r.URL.Host == "" {
		fullURL = "http://" + r.Host + r.URL.RequestURI()
	}

	rule := s.findMatch(r.Method, fullURL, string(bodyBytes))

	logEntry := RequestLog{
		Timestamp: time.Now(),
		Method:    r.Method,
		URL:       fullURL,
		Headers:   r.Header,
		Body:      string(bodyBytes),
	}

	if rule != nil {
		logEntry.MatchedRule = rule.Name
		logEntry.StatusCode = rule.Response.StatusCode
		s.appendLog(logEntry)
		s.sendMockResponse(w, rule.Response, bodyBytes)
	} else {
		// Forward the request to the real destination
		s.forwardRequest(w, r, bodyBytes, &logEntry)
	}
}

func (s *Server) findMatch(method, url, body string) *MockRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.rules {
		rule := &s.rules[i]
		if rule.Method != "" && rule.Method != method {
			continue
		}
		if rule.URLPattern != nil && !rule.URLPattern.MatchString(url) {
			continue
		}
		if rule.BodyPattern != nil && !rule.BodyPattern.MatchString(body) {
			continue
		}
		return rule
	}
	return nil
}

func (s *Server) sendMockResponse(w http.ResponseWriter, resp config.ResponseConfig, reqBody []byte) {
	if resp.Headers == nil {
		resp.Headers = map[string]string{}
	}
	if _, ok := resp.Headers["Content-Type"]; !ok {
		resp.Headers["Content-Type"] = "application/json"
	}
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}

	body := resp.Body

	// Dynamic merge: if response body is a map, merge request body fields
	if m, ok := deepCopyMap(body); ok {
		var reqData map[string]any
		if err := json.Unmarshal(reqBody, &reqData); err == nil {
			for k, v := range reqData {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		}
		body = m
	}

	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(body)
}

func deepCopyMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	cp := make(map[string]any, len(m))
	maps.Copy(cp, m)
	return cp, true
}

func (s *Server) forwardRequest(w http.ResponseWriter, r *http.Request, body []byte, logEntry *RequestLog) {
	outURL := r.URL.String()
	if r.URL.Host == "" {
		outURL = "http://" + r.Host + r.URL.RequestURI()
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, io.NopCloser(strings.NewReader(string(body))))
	if err != nil {
		logEntry.StatusCode = http.StatusBadGateway
		s.appendLog(*logEntry)
		http.Error(w, "failed to create forward request", http.StatusBadGateway)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Connection")

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		logEntry.StatusCode = http.StatusBadGateway
		s.appendLog(*logEntry)
		http.Error(w, fmt.Sprintf("proxy forward error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logEntry.StatusCode = resp.StatusCode
	s.appendLog(*logEntry)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}

	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}

	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(destConn, clientConn)
	}()
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, destConn)
	}()
}

// Admin endpoints

func (s *Server) handleAdmin(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")

	switch endpoint {
	case "logs":
		s.mu.RLock()
		logs := make([]RequestLog, len(s.logs))
		copy(logs, s.logs)
		s.mu.RUnlock()
		json.NewEncoder(w).Encode(logs)

	case "clear":
		s.mu.Lock()
		s.logs = make([]RequestLog, 0)
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})

	case "reload":
		ruleConfigs, err := config.LoadDir(s.configDir)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		rules, err := compileRules(ruleConfigs)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		s.mu.Lock()
		s.rules = rules
		s.mu.Unlock()
		log.Printf("Reloaded %d rules from %s", len(rules), s.configDir)
		json.NewEncoder(w).Encode(map[string]any{"status": "reloaded", "rules": len(rules)})

	case "health":
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown admin endpoint"})
	}
}

func (s *Server) appendLog(entry RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)
	logJSON, _ := json.MarshalIndent(entry, "", "  ")
	log.Printf("Request: %s", logJSON)
}
