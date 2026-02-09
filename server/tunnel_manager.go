package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/leviathan0992/spleen/util"
)

/* Manages all tunnel connections and public port mappings. */
type TunnelManager struct {
	listenAddr  string
	tlsConfig   *tls.Config
	globalToken string /* Shared token for dynamic clients */
	persistHook func([]MappingRule) error
	listenFunc  func(network, address string) (net.Listener, error)

	mu            sync.RWMutex
	clientPools   map[string]chan net.Conn /* clientID -> connection pool */
	clientStates  map[string]*ClientState  /* clientID -> state */
	mappingRules  map[string]*MappingRule  /* ruleID -> rule */
	portListeners map[int]net.Listener     /* public port -> listener */
	authGuard     map[string]*authGuardState
	authGuardMu   sync.Mutex

	connGuard   map[string]int /* ip -> active connection count */
	connGuardMu sync.Mutex

	stats struct {
		sync.RWMutex
		accepted    map[string]int64 /* clientID -> count */
		rejected    map[string]int64
		bytesIn     map[string]int64
		bytesOut    map[string]int64
		activeConns map[string]int64
		errors      map[string][]ErrorRecord
	}

	historyMu     sync.RWMutex
	publicHistory []ConnRecord
}

/* Represents a successful public connection. */
type ConnRecord struct {
	Time       time.Time `json:"time"`
	IP         string    `json:"ip"`
	Location   string    `json:"location"`
	RuleID     string    `json:"rule_id"`
	PublicPort int       `json:"public_port"`
	TargetPort int       `json:"target_port"`
	Success    bool      `json:"success"`
}

/* Tracks failed tunnel authentications per source IP. */
type authGuardState struct {
	WindowStart time.Time
	FailedCount int
	BanUntil    time.Time
}

/* Represents the current state of a connected client. */
type ClientState struct {
	ClientID    string    `json:"client_id"`
	Version     string    `json:"version"`
	LastSeen    time.Time `json:"last_seen"`
	Online      bool      `json:"online"`
	TunnelCount int       `json:"tunnel_count"`
	ActiveConns int64     `json:"active_conns"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
}

/* Stores error information for debugging. */
type ErrorRecord struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

/* Creates a new tunnel manager. */
func NewTunnelManager(listenAddr string, tlsConfig *tls.Config, globalToken string) *TunnelManager {
	m := &TunnelManager{
		listenAddr:    listenAddr,
		tlsConfig:     tlsConfig,
		globalToken:   globalToken,
		clientPools:   make(map[string]chan net.Conn),
		clientStates:  make(map[string]*ClientState),
		mappingRules:  make(map[string]*MappingRule),
		portListeners: make(map[int]net.Listener),
		authGuard:     make(map[string]*authGuardState),
		connGuard:     make(map[string]int),
		listenFunc:    net.Listen,
	}
	m.stats.accepted = make(map[string]int64)
	m.stats.rejected = make(map[string]int64)
	m.stats.bytesIn = make(map[string]int64)
	m.stats.bytesOut = make(map[string]int64)
	m.stats.activeConns = make(map[string]int64)
	m.stats.errors = make(map[string][]ErrorRecord)
	return m
}

/* Starts the tunnel server listener. */
func (m *TunnelManager) Start() error {
	listener, err := tls.Listen("tcp", m.listenAddr, m.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start tunnel listener: %w", err)
	}
	log.Printf("[INFO] Tunnel server started: %s", m.listenAddr)

	go m.cleanupLoop()
	go m.heartbeatCheck()
	go m.authGuardSweepLoop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Failed to accept connection: %v", err)
			continue
		}
		go m.handleClientConn(conn)
	}
}

/* Processes a new server connection. */
func (m *TunnelManager) handleClientConn(conn net.Conn) {
	closeOnReturn := true
	remoteIP := remoteHost(conn.RemoteAddr())
	defer func() {
		if closeOnReturn && conn != nil {
			_ = conn.Close()
		}
	}()

	reject := func(clientID, message string) {
		log.Printf("[WARN] Client %s (%s) authentication failed: %s", clientID, remoteIP, message)
		m.recordServerError(clientID, message, true)
		m.recordAuthFailure(remoteIP)
		_, _ = conn.Write([]byte(fmt.Sprintf(`{"status":"error","message":%q}`+"\n", message)))
	}

	if m.isAuthBanned(remoteIP) {
		_, _ = conn.Write([]byte(`{"status":"error","message":"source ip banned temporarily"}` + "\n"))
		return
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	nonce := util.GenerateNonce()
	challenge := map[string]string{"type": "challenge", "nonce": nonce}
	challengeBytes, _ := json.Marshal(challenge)
	if _, err := conn.Write(append(challengeBytes, '\n')); err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	authLine, err := util.ReadLineLimited(reader, 4096)
	if err != nil {
		m.recordAuthFailure(remoteIP)
		return
	}

	var authMsg util.AuthMessage
	if err := json.Unmarshal(authLine, &authMsg); err != nil {
		m.recordAuthFailure(remoteIP)
		return
	}
	authMsg.ClientID = util.NormalizeUUID(authMsg.ClientID)
	if !util.IsValidUUID(authMsg.ClientID) {
		reject(authMsg.ClientID, "invalid client_id")
		return
	}
	if authMsg.Type != "tunnel" && authMsg.Type != "ping" {
		reject(authMsg.ClientID, "invalid auth type")
		return
	}

	/* Authenticate using the single global server token. */
	if m.globalToken == "" || !util.VerifyTokenProof(m.globalToken, authMsg.ClientID, authMsg.Type, nonce, authMsg.TokenProof) {
		reject(authMsg.ClientID, "invalid token or authentication failed")
		return
	}

	/* Check if this is an existing client or a dynamic registration attempt. */
	m.mu.RLock()
	isExistingClient := false
	for _, rule := range m.mappingRules {
		if rule.ClientID == authMsg.ClientID {
			isExistingClient = true
			break
		}
	}
	m.mu.RUnlock()

	/* Only allow pre-configured clients. */
	if !isExistingClient {
		reject(authMsg.ClientID, "client not authorized: please add this ClientID to server's mapping_rules first")
		return
	}
	m.clearAuthFailures(remoteIP)

	if authMsg.Type == "ping" {
		log.Printf("[INFO] Heartbeat: Received from %s (%s)", authMsg.ClientID, remoteIP)
		m.markServerSeen(authMsg.ClientID, authMsg.Version)
		_, _ = conn.Write([]byte(`{"status":"ok","type":"pong"}` + "\n"))
		return
	}

	_, _ = conn.Write([]byte(`{"status":"ok"}` + "\n"))
	_ = conn.SetDeadline(time.Time{})

	log.Printf("[INFO] New tunnel connection accepted from %s (%s)", authMsg.ClientID, remoteIP)
	m.markServerSeen(authMsg.ClientID, authMsg.Version)
	m.recordAcceptedTunnel(authMsg.ClientID)

	/* Create pool with requested size (capped). */
	m.mu.Lock()
	pool, ok := m.clientPools[authMsg.ClientID]
	if !ok {
		poolSize := authMsg.PoolSize
		if poolSize <= 0 {
			poolSize = 10
		} else if poolSize > 1024 {
			poolSize = 1024
		}
		pool = make(chan net.Conn, poolSize)
		m.clientPools[authMsg.ClientID] = pool
	}
	m.mu.Unlock()

	select {
	case pool <- conn:
		closeOnReturn = false
		m.adjustIdleTunnels(authMsg.ClientID, 1)
	case <-time.After(10 * time.Second):
		log.Printf("[WARN] Tunnel pool full for client %s (cap %d). Rejecting connection.", authMsg.ClientID, cap(pool))
		m.recordServerError(authMsg.ClientID, "connection pool full", true)
	}
}

/* Applies mapping rules from config. */
func (m *TunnelManager) ApplyMappingRules(rules []MappingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nextRules := make(map[string]*MappingRule, len(rules))
	nextPorts := make(map[int]struct{})

	for i := range rules {
		ruleCopy := rules[i]
		if ruleCopy.ID == "" {
			log.Printf("[WARN] Skipping rule: ID cannot be empty (index %d)", i)
			continue
		}
		ruleCopy.ClientID = util.NormalizeUUID(ruleCopy.ClientID)
		if !util.IsValidUUID(ruleCopy.ClientID) {
			log.Printf("[WARN] Skipping rule %s: invalid client_id %q", ruleCopy.ID, ruleCopy.ClientID)
			continue
		}
		nextRules[ruleCopy.ID] = &ruleCopy
		nextPorts[ruleCopy.PublicPort] = struct{}{}
	}

	for port, listener := range m.portListeners {
		if _, keep := nextPorts[port]; !keep {
			_ = listener.Close()
			delete(m.portListeners, port)
		}
	}

	for _, rule := range nextRules {
		if err := m.startRuleListener(rule); err != nil {
			return err
		}
	}

	m.mappingRules = nextRules
	return nil
}

/* Starts a listener for a mapping rule if not already exists. */
func (m *TunnelManager) startRuleListener(rule *MappingRule) error {
	if _, exists := m.portListeners[rule.PublicPort]; exists {
		return nil
	}
	listener, err := m.listenFunc("tcp", fmt.Sprintf("0.0.0.0:%d", rule.PublicPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", rule.PublicPort, err)
	}
	m.portListeners[rule.PublicPort] = listener
	go m.acceptPublicConns(listener, rule.ClientID, rule.PublicPort, rule.TargetPort)
	log.Printf("[INFO] Mapping assigned: :%d -> :%d (UUID: %s)", rule.PublicPort, rule.TargetPort, util.NormalizeUUID(rule.ClientID)[:8])
	return nil
}

func (m *TunnelManager) SetListenerFactory(factory func(network, address string) (net.Listener, error)) {
	if factory == nil {
		m.listenFunc = net.Listen
		return
	}
	m.listenFunc = factory
}

/* Accepts connections on a public port. */
func (m *TunnelManager) acceptPublicConns(listener net.Listener, serverID string, publicPort, targetPort int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("[ERROR] Public listener accept failed: %v", err)
			return
		}
		go m.handlePublicConn(conn, serverID, publicPort, targetPort)
	}
}

/* Handles a connection from the public internet. */
func (m *TunnelManager) handlePublicConn(publicConn net.Conn, serverID string, publicPort, targetPort int) {
	defer publicConn.Close()

	remoteIP := remoteHost(publicConn.RemoteAddr())
	m.connGuardMu.Lock()
	if m.connGuard[remoteIP] >= 50 {
		m.connGuardMu.Unlock()
		m.recordServerError(serverID, fmt.Sprintf("too many connections from %s", remoteIP), true)
		return
	}
	m.connGuard[remoteIP]++
	m.connGuardMu.Unlock()

	defer func() {
		m.connGuardMu.Lock()
		m.connGuard[remoteIP]--
		if m.connGuard[remoteIP] <= 0 {
			delete(m.connGuard, remoteIP)
		}
		m.connGuardMu.Unlock()
	}()

	m.mu.RLock()
	pool, ok := m.clientPools[serverID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	var tunnelConn net.Conn
	select {
	case tunnelConn = <-pool:
		m.adjustIdleTunnels(serverID, -1)
	case <-time.After(5 * time.Second):
		m.recordServerError(serverID, "timeout obtaining tunnel connection", false)
		m.AddPublicConnHistory(remoteHost(publicConn.RemoteAddr()), serverID, publicPort, targetPort, false)
		return
	}

	if tunnelConn == nil {
		m.AddPublicConnHistory(remoteHost(publicConn.RemoteAddr()), serverID, publicPort, targetPort, false)
		return
	}
	defer tunnelConn.Close()

	targetMsg := map[string]interface{}{"type": "forward", "target_port": targetPort}
	targetBytes, _ := json.Marshal(targetMsg)
	if _, err := tunnelConn.Write(append(targetBytes, '\n')); err != nil {
		log.Printf("[ERROR] Failed to write forward request to tunnel: %v", err)
		return
	}

	/* Record success in history after handshake. */
	m.AddPublicConnHistory(remoteHost(publicConn.RemoteAddr()), serverID, publicPort, targetPort, true)

	m.adjustActiveConns(serverID, 1)
	defer m.adjustActiveConns(serverID, -1)

	errCh := make(chan error, 2)
	go func() {
		n, err := util.TransferCount(publicConn, tunnelConn)
		m.addBytesIn(serverID, n)
		errCh <- err
	}()
	go func() {
		n, err := util.TransferCount(tunnelConn, publicConn)
		m.addBytesOut(serverID, n)
		errCh <- err
	}()
	<-errCh
}

/* Updates server last seen time. */
func (m *TunnelManager) markServerSeen(serverID, version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.clientStates[serverID]
	if !ok {
		state = &ClientState{ClientID: serverID}
		m.clientStates[serverID] = state
	}
	state.LastSeen = time.Now()
	state.Version = version
	state.Online = true
}

/* Adjusts the idle tunnel count. */
func (m *TunnelManager) adjustIdleTunnels(serverID string, delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.clientStates[serverID]; ok {
		state.TunnelCount += delta
		if state.TunnelCount < 0 {
			state.TunnelCount = 0
		}
	}
}

/* Adjusts the active connection count. */
func (m *TunnelManager) adjustActiveConns(serverID string, delta int64) {
	m.stats.Lock()
	defer m.stats.Unlock()
	m.stats.activeConns[serverID] += delta
}

/* Adds bytes received count. */
func (m *TunnelManager) addBytesIn(serverID string, n int64) {
	m.stats.Lock()
	defer m.stats.Unlock()
	m.stats.bytesIn[serverID] += n
}

/* Adds bytes sent count. */
func (m *TunnelManager) addBytesOut(serverID string, n int64) {
	m.stats.Lock()
	defer m.stats.Unlock()
	m.stats.bytesOut[serverID] += n
}

/* Records a successful tunnel connection. */
func (m *TunnelManager) recordAcceptedTunnel(serverID string) {
	m.stats.Lock()
	defer m.stats.Unlock()
	m.stats.accepted[serverID]++
}

/* Records an error for a server. */
func (m *TunnelManager) recordServerError(serverID, message string, isRejection bool) {
	m.stats.Lock()
	defer m.stats.Unlock()
	if isRejection {
		m.stats.rejected[serverID]++
	}
	errs := m.stats.errors[serverID]
	errs = append(errs, ErrorRecord{Time: time.Now(), Message: message})
	if len(errs) > 100 {
		errs = errs[len(errs)-100:]
	}
	m.stats.errors[serverID] = errs
}

/* Periodically cleans up stale connections. */
func (m *TunnelManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		/* Snapshot pools to avoid holding lock during IO. */
		m.mu.RLock()
		pools := make(map[string]chan net.Conn, len(m.clientPools))
		for k, v := range m.clientPools {
			pools[k] = v
		}
		m.mu.RUnlock()

		for serverID, pool := range pools {
			currentLen := len(pool)
			for i := 0; i < currentLen; i++ {
				select {
				case conn := <-pool:
					_ = conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
					buf := make([]byte, 1)
					_, err := conn.Read(buf)
					_ = conn.SetReadDeadline(time.Time{})

					if err == nil {
						/* Unexpected data: treat as broken/dirty. */
						_ = conn.Close()
						m.decrementTunnelCount(serverID)
					} else if err != io.EOF {
						/* Timeout/No data: connection is healthy (idle). */
						select {
						case pool <- conn:
						default:
							/* Pool fulled up in meantime? Should not happen logically but handle it. */
							_ = conn.Close()
							m.decrementTunnelCount(serverID)
						}
					} else {
						/* EOF: Connection closed. */
						_ = conn.Close()
						m.decrementTunnelCount(serverID)
					}
				default:
					/* Pool empty, move to next. */
				}
			}
		}
	}
}

func (m *TunnelManager) decrementTunnelCount(serverID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.clientStates[serverID]; ok && state.TunnelCount > 0 {
		state.TunnelCount--
	}
}

/* Marks servers as offline if not seen recently. */
func (m *TunnelManager) heartbeatCheck() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		for _, state := range m.clientStates {
			if time.Since(state.LastSeen) > 60*time.Second {
				state.Online = false
			}
		}
		m.mu.Unlock()
	}
}

/* Returns a snapshot of all server states. */
func (m *TunnelManager) SnapshotServers() []ClientState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.stats.RLock()
	defer m.stats.RUnlock()

	result := make([]ClientState, 0, len(m.clientStates))
	for _, state := range m.clientStates {
		s := *state
		s.ActiveConns = m.stats.activeConns[s.ClientID]
		s.BytesIn = m.stats.bytesIn[s.ClientID]
		s.BytesOut = m.stats.bytesOut[s.ClientID]
		result = append(result, s)
	}
	return result
}

/* Returns tunnel statistics. */
func (m *TunnelManager) GetStats() map[string]interface{} {
	m.stats.RLock()
	defer m.stats.RUnlock()

	var totalAccepted, totalRejected, totalBytesIn, totalBytesOut int64
	for _, v := range m.stats.accepted {
		totalAccepted += v
	}
	for _, v := range m.stats.rejected {
		totalRejected += v
	}
	for _, v := range m.stats.bytesIn {
		totalBytesIn += v
	}
	for _, v := range m.stats.bytesOut {
		totalBytesOut += v
	}

	return map[string]interface{}{
		"total_accepted":  totalAccepted,
		"total_rejected":  totalRejected,
		"total_bytes_in":  totalBytesIn,
		"total_bytes_out": totalBytesOut,
	}
}

func (m *TunnelManager) SetRulesPersistHook(hook func([]MappingRule) error) {
	m.persistHook = hook
}

func (m *TunnelManager) SnapshotMappingRules() []MappingRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshotRulesLocked()
}

func (m *TunnelManager) snapshotRulesLocked() []MappingRule {
	out := make([]MappingRule, 0, len(m.mappingRules))
	for _, rule := range m.mappingRules {
		out = append(out, *rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PublicPort == out[j].PublicPort {
			return out[i].ID < out[j].ID
		}
		return out[i].PublicPort < out[j].PublicPort
	})
	return out
}

func (m *TunnelManager) authGuardSweepLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.authGuardMu.Lock()
		for ip, state := range m.authGuard {
			windowExpired := !state.WindowStart.IsZero() && now.Sub(state.WindowStart) > 30*time.Minute
			banExpired := state.BanUntil.IsZero() || !state.BanUntil.After(now)
			if windowExpired && banExpired {
				delete(m.authGuard, ip)
			}
		}
		m.authGuardMu.Unlock()
	}
}

func (m *TunnelManager) isAuthBanned(ip string) bool {
	m.authGuardMu.Lock()
	defer m.authGuardMu.Unlock()
	state, ok := m.authGuard[ip]
	if !ok {
		return false
	}
	return time.Now().Before(state.BanUntil)
}

func (m *TunnelManager) recordAuthFailure(ip string) {
	m.authGuardMu.Lock()
	defer m.authGuardMu.Unlock()
	state, ok := m.authGuard[ip]
	if !ok {
		state = &authGuardState{WindowStart: time.Now()}
		m.authGuard[ip] = state
	}
	if time.Since(state.WindowStart) > 15*time.Minute {
		state.WindowStart = time.Now()
		state.FailedCount = 0
	}
	state.FailedCount++
	if state.FailedCount >= 8 {
		state.BanUntil = time.Now().Add(20 * time.Minute)
	}
}

func (m *TunnelManager) clearAuthFailures(ip string) {
	m.authGuardMu.Lock()
	defer m.authGuardMu.Unlock()
	delete(m.authGuard, ip)
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

/* Adds a connection record to the history. */
func (m *TunnelManager) AddPublicConnHistory(ip, clientID string, publicPort, targetPort int, success bool) {
	m.mu.RLock()
	var ruleID string
	for _, rule := range m.mappingRules {
		if rule.ClientID == clientID && rule.TargetPort == targetPort && rule.PublicPort == publicPort {
			ruleID = rule.ID
			break
		}
	}
	m.mu.RUnlock()

	record := ConnRecord{
		Time:       time.Now(),
		IP:         ip,
		RuleID:     ruleID,
		PublicPort: publicPort,
		TargetPort: targetPort,
		Success:    success,
		Location:   "Checking...",
	}

	m.historyMu.Lock()
	m.publicHistory = append(m.publicHistory, record)
	if len(m.publicHistory) > 100 {
		m.publicHistory = m.publicHistory[len(m.publicHistory)-100:]
	}
	m.historyMu.Unlock()
}

/* Returns the recent connection history. */
func (m *TunnelManager) GetPublicHistory() []ConnRecord {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()
	out := make([]ConnRecord, len(m.publicHistory))
	copy(out, m.publicHistory)
	/* Reverse for dashboard display (newest first). */
	for i := 0; i < len(out)/2; i++ {
		j := len(out) - 1 - i
		out[i], out[j] = out[j], out[i]
	}
	return out
}

/* Updates the location for records with a specific IP. */
func (m *TunnelManager) UpdateLocation(ip, location string) {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()
	for i := range m.publicHistory {
		if m.publicHistory[i].IP == ip && (m.publicHistory[i].Location == "" || m.publicHistory[i].Location == "Checking...") {
			m.publicHistory[i].Location = location
		}
	}
}
