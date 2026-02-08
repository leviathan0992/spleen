package main

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

/* Stores web panel configuration. */
type PanelConfig struct {
	ListenAddress string `json:"dashboard_addr"`
	Username      string `json:"dashboard_user"`
	Password      string `json:"dashboard_pwd"`
}

/* Represents one public-to-private mapping. */
type MappingRule struct {
	ID         string `json:"id"`
	ClientID   string `json:"client_id"`
	PublicPort int    `json:"public_port"`
	TargetPort int    `json:"target_port"`
	Remark     string `json:"remark"`
}

/* Holds persistent panel state. */
type DataStore struct {
	Panel               PanelConfig   `json:"panel"`
	TunnelListenAddress string        `json:"tunnel_listen_address"`
	Token               string        `json:"token"`
	MappingRules        []MappingRule `json:"mapping_rules"`

	mu       sync.RWMutex
	filePath string
}

/* Represents an authenticated web session. */
type Session struct {
	Token     string
	ExpiresAt time.Time
}

/* Tracks failed login attempts. */
type loginGuardState struct {
	WindowStart time.Time
	FailedCount int
	BanUntil    time.Time
}

/* Serves APIs and embedded static pages. */
type WebPanel struct {
	data       *DataStore
	tunnel     *TunnelManager
	sessions   map[string]*Session
	sessionMu  sync.RWMutex
	startTime  time.Time
	loginMu    sync.Mutex
	loginGuard map[string]*loginGuardState
	geoCache   map[string]string
	geoMu      sync.RWMutex
}

func NewWebPanel(dataPath string) (*WebPanel, error) {
	data := &DataStore{
		filePath: dataPath,
		Panel: PanelConfig{
			ListenAddress: "0.0.0.0:54321",
			Username:      "admin",
			Password:      "admin",
		},
		TunnelListenAddress: "0.0.0.0:5432",
		MappingRules:        []MappingRule{},
	}

	if fileData, err := os.ReadFile(dataPath); err == nil {
		if err := json.Unmarshal(fileData, data); err != nil {
			log.Printf("[WARN] Failed to parse configuration file %s: %v", dataPath, err)
		}
	} else if os.IsNotExist(err) {
		/* Config file not found, create default. */
		log.Printf("[INIT] Config file missing, using defaults")
	} else {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	wp := &WebPanel{
		data:       data,
		sessions:   make(map[string]*Session),
		startTime:  time.Now(),
		loginGuard: make(map[string]*loginGuardState),
		geoCache:   make(map[string]string),
	}
	return wp, nil
}

func (wp *WebPanel) SetTunnelManager(tunnel *TunnelManager) {
	wp.tunnel = tunnel
}

func (wp *WebPanel) SetGlobalToken(token string) {
	wp.data.mu.Lock()
	defer wp.data.mu.Unlock()
	wp.data.Token = token
}

func (wp *WebPanel) ReplaceMappingRules(rules []MappingRule) error {
	wp.data.mu.Lock()
	defer wp.data.mu.Unlock()
	wp.data.MappingRules = make([]MappingRule, len(rules))
	copy(wp.data.MappingRules, rules)
	return wp.data.saveUnlocked()
}

func (d *DataStore) Save() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.saveUnlocked()
}

func (d *DataStore) saveUnlocked() error {
	payload, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	/* Ensure parent directory exists. */
	dir := filepath.Dir(d.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(d.filePath, payload, 0600)
}

func (wp *WebPanel) GetMappingRules() []MappingRule {
	wp.data.mu.RLock()
	defer wp.data.mu.RUnlock()
	rules := make([]MappingRule, len(wp.data.MappingRules))
	copy(rules, wp.data.MappingRules)
	return rules
}

func (wp *WebPanel) GetTunnelListenAddress() string {
	wp.data.mu.RLock()
	defer wp.data.mu.RUnlock()
	return wp.data.TunnelListenAddress
}

func (wp *WebPanel) GetPanelListenAddress() string {
	wp.data.mu.RLock()
	defer wp.data.mu.RUnlock()
	return wp.data.Panel.ListenAddress
}

/* Starts the web panel HTTP server. */
func (wp *WebPanel) Start() error {
	return wp.StartWithTLS(nil, "", "")
}

/* Starts the web panel with optional HTTPS. */
func (wp *WebPanel) StartWithTLS(tlsConfig *tls.Config, certFile, keyFile string) error {
	mux := http.NewServeMux()

	/* Public endpoints */
	mux.HandleFunc("/", wp.handlePage)
	mux.HandleFunc("/api/login", wp.handleLogin)
	mux.HandleFunc("/api/logout", wp.handleLogout)

	/* Protected endpoints */
	mux.HandleFunc("/api/status", wp.authMiddleware(wp.handleStatus))
	mux.HandleFunc("/api/servers", wp.authMiddleware(wp.handleServers))
	mux.HandleFunc("/api/mapping_rules", wp.authMiddleware(wp.handleMappingRules))
	mux.HandleFunc("/api/security", wp.authMiddleware(wp.handleSecurity))
	mux.HandleFunc("/api/history", wp.authMiddleware(wp.handleHistory))

	addr := wp.GetPanelListenAddress()
	go wp.sessionAndGuardSweepLoop()
	go wp.geoIPWorker()

	if tlsConfig != nil && certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(addr, certFile, keyFile, mux)
	}
	return http.ListenAndServe(addr, mux)
}

func (wp *WebPanel) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return
		}
		wp.sessionMu.RLock()
		session, ok := wp.sessions[cookie.Value]
		wp.sessionMu.RUnlock()
		if !ok || time.Now().After(session.ExpiresAt) {
			if ok {
				wp.sessionMu.Lock()
				delete(wp.sessions, cookie.Value)
				wp.sessionMu.Unlock()
			}
			http.Error(w, "会话过期", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (wp *WebPanel) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(staticHTML))
}

func (wp *WebPanel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	clientIP := getClientIP(r)
	if wp.isLoginBanned(clientIP) {
		jsonError(w, "登录尝试次数过多，请稍后再试", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "请求格式错误", http.StatusBadRequest)
		return
	}

	username := wp.data.Panel.Username
	storedPassword := wp.data.Panel.Password

	if subtle.ConstantTimeCompare([]byte(req.Username), []byte(username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(req.Password), []byte(storedPassword)) != 1 {
		wp.recordLoginFailure(clientIP)
		jsonError(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	wp.clearLoginFailures(clientIP)

	token := generateToken(32)
	session := &Session{
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	wp.sessionMu.Lock()
	wp.sessions[token] = session
	wp.sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		Expires:  session.ExpiresAt,
	})

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (wp *WebPanel) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		wp.sessionMu.Lock()
		delete(wp.sessions, cookie.Value)
		wp.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (wp *WebPanel) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	rulesCount := len(wp.data.MappingRules)
	var onlineServers, offlineServers int
	if wp.tunnel != nil {
		for _, s := range wp.tunnel.SnapshotServers() {
			if s.Online {
				onlineServers++
			} else {
				offlineServers++
			}
		}
	}

	var guardSummary string
	wp.loginMu.Lock()
	bannedCount := 0
	for _, state := range wp.loginGuard {
		if time.Now().Before(state.BanUntil) {
			bannedCount++
		}
	}
	wp.loginMu.Unlock()
	if bannedCount > 0 {
		guardSummary = fmt.Sprintf("已封禁 %d 个IP", bannedCount)
	} else {
		guardSummary = "正常"
	}

	jsonResponse(w, map[string]interface{}{
		"uptime":           time.Since(wp.startTime).Seconds(),
		"system_ip":        getOutboundIP(),
		"rules_count":      rulesCount,
		"online_servers":   onlineServers,
		"offline_servers":  offlineServers,
		"security_summary": guardSummary,
		"read_only":        true, /* Dashboard is read-only */
	})
}

func (wp *WebPanel) handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if wp.tunnel == nil {
		jsonResponse(w, map[string]interface{}{"servers": []interface{}{}})
		return
	}

	/* Only return necessary info, hide sensitive data like ClientID. */
	type SafeServer struct {
		Online      bool   `json:"online"`
		TunnelCount int    `json:"tunnel_count"`
		ActiveConns int64  `json:"active_conns"`
		LastSeen    string `json:"last_seen"`
	}

	servers := wp.tunnel.SnapshotServers()
	safeServers := make([]SafeServer, len(servers))
	for i, s := range servers {
		safeServers[i] = SafeServer{
			Online:      s.Online,
			TunnelCount: s.TunnelCount,
			ActiveConns: s.ActiveConns,
			LastSeen:    s.LastSeen.Format("15:04:05"),
		}
	}
	jsonResponse(w, map[string]interface{}{"servers": safeServers})
}

func (wp *WebPanel) handleMappingRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "只读模式：请通过配置文件管理规则", http.StatusForbidden)
		return
	}

	rules := make([]MappingRule, 0)
	if wp.tunnel != nil {
		rules = wp.tunnel.SnapshotMappingRules()
	} else {
		wp.data.mu.RLock()
		rules = make([]MappingRule, len(wp.data.MappingRules))
		copy(rules, wp.data.MappingRules)
		wp.data.mu.RUnlock()
	}

	/* Only return necessary info, hide sensitive data. */
	type SafeRule struct {
		ID         string `json:"id"`
		ClientID   string `json:"client_id"`
		PublicPort int    `json:"public_port"`
		TargetPort int    `json:"target_port"`
		Remark     string `json:"remark"`
	}

	safeRules := make([]SafeRule, len(rules))
	for i, r := range rules {
		maskedID := shortUUID(r.ClientID)
		safeRules[i] = SafeRule{
			ID:         r.ID,
			ClientID:   maskedID,
			PublicPort: r.PublicPort,
			TargetPort: r.TargetPort,
			Remark:     r.Remark,
		}
	}
	jsonResponse(w, safeRules)
}

func (wp *WebPanel) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	wp.loginMu.Lock()
	banned := make([]map[string]interface{}, 0)
	for ip, state := range wp.loginGuard {
		if time.Now().Before(state.BanUntil) {
			banned = append(banned, map[string]interface{}{
				"ip":         ip,
				"ban_until":  state.BanUntil.Format(time.RFC3339),
				"fail_count": state.FailedCount,
			})
		}
	}
	wp.loginMu.Unlock()

	var tunnelStats map[string]interface{}
	if wp.tunnel != nil {
		tunnelStats = wp.tunnel.GetStats()
	} else {
		tunnelStats = map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{
		"banned_ips":   banned,
		"tunnel_stats": tunnelStats,
	})
}

func (wp *WebPanel) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	if wp.tunnel == nil {
		jsonResponse(w, []interface{}{})
		return
	}

	history := wp.tunnel.GetPublicHistory()
	/* Format time for display. */
	type DisplayRecord struct {
		Time     string `json:"time"`
		IP       string `json:"ip"`
		Location string `json:"location"`
		RuleID   string `json:"rule_id"`
		Public   string `json:"public"`
		Target   string `json:"target"`
		Status   bool   `json:"status"`
	}

	display := make([]DisplayRecord, len(history))
	for i, h := range history {
		display[i] = DisplayRecord{
			Time:     h.Time.Format("01-02 15:04:05"),
			IP:       h.IP,
			Location: h.Location,
			RuleID:   h.RuleID,
			Public:   fmt.Sprintf(":%d", h.PublicPort),
			Target:   fmt.Sprintf(":%d", h.TargetPort),
			Status:   h.Success,
		}
	}

	jsonResponse(w, display)
}

func (wp *WebPanel) geoIPWorker() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if wp.tunnel == nil {
			continue
		}
		history := wp.tunnel.GetPublicHistory()
		for _, h := range history {
			if h.Location == "Checking..." || h.Location == "" {
				loc := wp.resolveGeoIP(h.IP)
				if loc != "" {
					wp.tunnel.UpdateLocation(h.IP, loc)
				}
			}
		}
	}
}

func (wp *WebPanel) resolveGeoIP(ip string) string {
	if ip == "127.0.0.1" || ip == "localhost" || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "局域网"
	}

	wp.geoMu.RLock()
	loc, ok := wp.geoCache[ip]
	wp.geoMu.RUnlock()
	if ok {
		return loc
	}

	/* Fetch from API. */
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		Region  string `json:"regionName"`
		City    string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	if result.Status != "success" {
		return "未知"
	}

	finalLoc := fmt.Sprintf("%s %s %s", result.Country, result.Region, result.City)
	finalLoc = strings.TrimSpace(finalLoc)

	wp.geoMu.Lock()
	wp.geoCache[ip] = finalLoc
	wp.geoMu.Unlock()
	return finalLoc
}

func (wp *WebPanel) sessionAndGuardSweepLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		wp.sessionMu.Lock()
		for token, session := range wp.sessions {
			if now.After(session.ExpiresAt) {
				delete(wp.sessions, token)
			}
		}
		wp.sessionMu.Unlock()

		wp.loginMu.Lock()
		for ip, state := range wp.loginGuard {
			windowExpired := !state.WindowStart.IsZero() && now.Sub(state.WindowStart) > 30*time.Minute
			banExpired := state.BanUntil.IsZero() || !state.BanUntil.After(now)
			noFailures := state.FailedCount == 0
			if windowExpired && banExpired && noFailures {
				delete(wp.loginGuard, ip)
			}
		}
		wp.loginMu.Unlock()
	}
}

/* Login guard functions */
func (wp *WebPanel) isLoginBanned(ip string) bool {
	wp.loginMu.Lock()
	defer wp.loginMu.Unlock()
	state, ok := wp.loginGuard[ip]
	if !ok {
		return false
	}
	return time.Now().Before(state.BanUntil)
}

func (wp *WebPanel) recordLoginFailure(ip string) {
	wp.loginMu.Lock()
	defer wp.loginMu.Unlock()
	state, ok := wp.loginGuard[ip]
	if !ok {
		state = &loginGuardState{WindowStart: time.Now()}
		wp.loginGuard[ip] = state
	}
	if time.Since(state.WindowStart) > 15*time.Minute {
		state.WindowStart = time.Now()
		state.FailedCount = 0
	}
	state.FailedCount++
	if state.FailedCount >= 5 {
		state.BanUntil = time.Now().Add(15 * time.Minute)
	}
}

func (wp *WebPanel) clearLoginFailures(ip string) {
	wp.loginMu.Lock()
	defer wp.loginMu.Unlock()
	delete(wp.loginGuard, ip)
}

/* Utility functions */

func generateToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func getOutboundIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "Unknown"
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return "Unknown"
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func shortUUID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return v
	}
	return strings.ToUpper(v[:8]) + "..."
}
