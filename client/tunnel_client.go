package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/leviathan1995/spleen/util"
)

/* TunnelClient maintains connections to the tunnel server. */
type TunnelClient struct {
	serverAddr string
	clientID   string
	token      string
	poolSize   int
	tlsConfig  *tls.Config

	mu              sync.Mutex
	activeTunnels   int
	peerFingerprint string
}

/* NewTunnelClient creates a new tunnel client. */
func NewTunnelClient(serverAddr, clientID, token string, poolSize int) *TunnelClient {
	c := &TunnelClient{
		serverAddr: serverAddr,
		clientID:   clientID,
		token:      token,
		poolSize:   poolSize,
	}

	c.tlsConfig = &tls.Config{
		InsecureSkipVerify: true, /* We verify fingerprint manually in VerifyConnection. */
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return c.verifyPeerFingerprint(cs)
		},
	}
	return c
}

/* Run starts tunnel maintenance and heartbeat loops. */
func (c *TunnelClient) Run() {
	go c.heartbeatLoop()

	for {
		c.maintainPool()
		time.Sleep(1 * time.Second)
	}
}

/* maintainPool ensures we have enough tunnels in the pool. */
func (c *TunnelClient) maintainPool() {
	c.mu.Lock()
	needed := c.poolSize - c.activeTunnels
	c.mu.Unlock()

	for i := 0; i < needed; i++ {
		go c.createTunnel()
	}
}

/* createTunnel creates a single tunnel connection. */
func (c *TunnelClient) createTunnel() {
	c.mu.Lock()
	c.activeTunnels++
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.activeTunnels--
		c.mu.Unlock()
	}()

	conn, err := c.dialTunnelServer()
	if err != nil {
		log.Printf("[ERROR] Failed to create tunnel: %v", err)
		time.Sleep(5 * time.Second)
		return
	}
	defer conn.Close()

	/* Wait for forward request. */
	reader := bufio.NewReader(conn)
	line, err := util.ReadLineLimited(reader, 4096)
	if err != nil {
		return
	}

	var msg struct {
		Type       string `json:"type"`
		TargetPort int    `json:"target_port"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return
	}

	if msg.Type != "forward" {
		return
	}

	/* Connect to local target. */
	targetAddr := fmt.Sprintf("127.0.0.1:%d", msg.TargetPort)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("[ERROR] Failed to connect local target: %v", err)
		return
	}
	defer targetConn.Close()

	/* Bidirectional transfer. */
	errCh := make(chan error, 2)
	go func() {
		/* Use util.Transfer for zero-allocation buffer pooling. */
		err := util.Transfer(reader, targetConn)
		errCh <- err
	}()
	go func() {
		err := util.Transfer(targetConn, conn)
		errCh <- err
	}()

	<-errCh
}

/* dialTunnelServer establishes a TLS connection and authenticates. */
func (c *TunnelClient) dialTunnelServer() (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", c.serverAddr, c.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}

	/* Read challenge. */
	reader := bufio.NewReader(conn)
	challengeLine, err := util.ReadLineLimited(reader, 4096)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read challenge: %w", err)
	}

	var challenge struct {
		Type  string `json:"type"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(challengeLine, &challenge); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to parse challenge: %w", err)
	}

	/* Send auth response. */
	if challenge.Type != "challenge" || challenge.Nonce == "" {
		conn.Close()
		return nil, fmt.Errorf("invalid challenge from server")
	}
	proof := util.BuildTokenProof(c.token, c.clientID, "tunnel", challenge.Nonce)

	authMsg := util.AuthMessage{
		ClientID:   c.clientID,
		Type:       "tunnel",
		Version:    "1.0.0",
		PoolSize:   c.poolSize,
		TokenProof: proof,
	}
	authBytes, _ := json.Marshal(authMsg)

	if _, err := conn.Write(append(authBytes, '\n')); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send authentication: %w", err)
	}

	/* Read response. */
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respLine, err := util.ReadLineLimited(reader, 4096)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read authentication response: %w", err)
	}

	var resp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respLine, &resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to parse authentication response: %w", err)
	}

	if resp.Status != "ok" {
		conn.Close()
		return nil, fmt.Errorf("authentication failed: %s", resp.Message)
	}

	return conn, nil
}

/* verifyPeerFingerprint verifies the server's certificate fingerprint (TOFU with persistence). */
func (c *TunnelClient) verifyPeerFingerprint(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("server provided no certificates")
	}

	fingerprint := util.GetCertFingerprint(cs.PeerCertificates[0])

	/* Ensure data directory exists */
	const dataDir = "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		_ = os.Mkdir(dataDir, 0755)
	}
	fingerprintFile := filepath.Join(dataDir, ".spleen_fingerprint")

	c.mu.Lock()
	defer c.mu.Unlock()

	/* 1. Check memory cache first. */
	if c.peerFingerprint != "" {
		if c.peerFingerprint != fingerprint {
			return fmt.Errorf("⚠️ [FATAL] FATAL SECURITY WARNING: Server fingerprint mismatch! Potential Man-in-the-Middle attack.\nExpected: %s\nActual: %s", c.peerFingerprint, fingerprint)
		}
		return nil
	}

	/* 2. Check persistence file. */
	if data, err := os.ReadFile(fingerprintFile); err == nil {
		storedFingerprint := string(data)
		if storedFingerprint != fingerprint {
			return fmt.Errorf("⚠️ [FATAL] FATAL SECURITY WARNING: Server fingerprint mismatch! Potential Man-in-the-Middle attack.\nExpected (stored): %s\nActual: %s", storedFingerprint, fingerprint)
		}
		c.peerFingerprint = fingerprint
		return nil
	}

	/* 3. First use (TOFU) - Save to file. */
	if err := os.WriteFile(fingerprintFile, []byte(fingerprint), 0600); err != nil {
		log.Printf("[WARN] Failed to persist fingerprint to file: %v", err)
	}

	c.peerFingerprint = fingerprint
	log.Printf("[INFO] TOFU: 首次信任并保存服务器指纹: %s", fingerprint)
	return nil
}

/* heartbeatLoop sends periodic heartbeats. */
func (c *TunnelClient) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := c.sendHeartbeat(); err != nil {
			log.Printf("[WARN] Heartbeat failed: %v", err)
		}
	}
}

/* sendHeartbeat sends a heartbeat to the server. */
func (c *TunnelClient) sendHeartbeat() error {
	conn, err := tls.Dial("tcp", c.serverAddr, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("heartbeat connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	/* Read challenge. */
	reader := bufio.NewReader(conn)
	challengeLine, err := util.ReadLineLimited(reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to read heartbeat challenge: %w", err)
	}

	var challenge struct {
		Type  string `json:"type"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(challengeLine, &challenge); err != nil {
		return fmt.Errorf("failed to parse heartbeat challenge: %w", err)
	}
	if challenge.Type != "challenge" || challenge.Nonce == "" {
		return fmt.Errorf("invalid heartbeat challenge")
	}

	/* Send ping. */
	proof := util.BuildTokenProof(c.token, c.clientID, "ping", challenge.Nonce)

	authMsg := util.AuthMessage{
		ClientID:   c.clientID,
		Type:       "ping",
		Version:    "1.0.0",
		TokenProof: proof,
	}
	authBytes, _ := json.Marshal(authMsg)
	if _, err := conn.Write(append(authBytes, '\n')); err != nil {
		return fmt.Errorf("failed to send heartbeat auth: %w", err)
	}

	respLine, err := util.ReadLineLimited(reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to read heartbeat response: %w", err)
	}
	var resp struct {
		Status string `json:"status"`
		Type   string `json:"type"`
	}
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return fmt.Errorf("failed to parse heartbeat response: %w", err)
	}
	if resp.Status != "ok" || resp.Type != "pong" {
		return fmt.Errorf("heartbeat rejected")
	}

	return nil
}

/* LoadClientConfig loads client configuration from a JSON file. */
func LoadClientConfig(path string) (serverAddr, clientID, token string, poolSize int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", 0, err
	}

	var config struct {
		ServerAddr string `json:"server_addr"`
		ClientID   string `json:"client_id"`
		Token      string `json:"token"`
		PoolSize   int    `json:"pool_size"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return "", "", "", 0, err
	}

	if config.PoolSize <= 0 {
		config.PoolSize = 10
	}

	return config.ServerAddr, util.NormalizeUUID(config.ClientID), config.Token, config.PoolSize, nil
}
