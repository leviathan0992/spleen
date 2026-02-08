package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leviathan1995/spleen/util"
)

const Version = "1.0.0"

func main() {
	configPath := flag.String("d", ".spleen-server.json", "Path to configuration file")
	clean := flag.Bool("clean", false, "Clear state files and re-initialize")
	version := flag.Bool("version", false, "Show version information")

	/* Utility flags */
	genPwd := flag.String("gen-pwd", "", "Generate and print password hash for config")
	/* genToken removed as we use plaintext token now. */
	genSecret := flag.Bool("gen-secret", false, "Generate and print a random strong secret for Token")
	genID := flag.Bool("gen-id", false, "Generate and print a new UUID for ClientID")
	initConfigs := flag.Bool("init", false, "Generate default server and client config files (Recommended)")
	quickToken := flag.String("token", "", "Quick-Join mode: Set global access Token")

	flag.Parse()

	if *version {
		fmt.Printf("spleen-server version %s\n", Version)
		return
	}

	if *initConfigs {
		generateDefaultConfigs()
		return
	}

	if *genID {
		fmt.Println(util.GenerateUUID())
		return
	}

	if *genSecret {
		/* Generate 32-char hex string. */
		fmt.Println(util.GenerateNonce() + util.GenerateNonce())
		return
	}

	/* *genToken check removed. */

	if *genPwd != "" {
		fmt.Println(hashPassword(*genPwd))
		return
	}

	if *clean {
		fmt.Println("[INIT] Cleaning up state files...")
		os.Remove(filepath.Join("data", ".spleen-server-cert.pem"))
		os.Remove(filepath.Join("data", ".spleen-server-key.pem"))
	}

	/* Create or load Web Panel. */
	wp, err := NewWebPanel(*configPath)
	if err != nil {
		fmt.Printf("[FATAL] Initialization failed: %v\n", err)
		os.Exit(1)
	}

	/* Load Global Token if provided via flag */
	if *quickToken != "" {
		fmt.Println("[INIT] Quick-Join mode enabled")
		wp.SetGlobalToken(*quickToken)
	}

	/* Generate or load TLS certificates. */
	tlsConfig, certExpiry, err := loadOrCreateTLSConfig()
	if err != nil {
		fmt.Printf("[FATAL] TLS initialization failed: %v\n", err)
		os.Exit(1)
	}

	/* Create tunnel manager. */
	tunnelAddr := wp.GetTunnelListenAddress()
	globalToken := wp.data.Token
	tunnel := NewTunnelManager(tunnelAddr, tlsConfig, globalToken)
	tunnel.SetRulesPersistHook(wp.ReplaceMappingRules)
	wp.SetTunnelManager(tunnel)

	/* Apply mapping rules. */
	rules := wp.GetMappingRules()
	if len(rules) > 0 {
		if err := tunnel.ApplyMappingRules(rules); err != nil {
			fmt.Printf("[FATAL] Failed to apply mapping rules: %v\n", err)
			os.Exit(1)
		}
	}

	/* Print startup banner. */
	printBanner(wp.GetPanelListenAddress(), tunnelAddr, *configPath, len(rules), certExpiry, false)

	/* Start tunnel server. */
	go func() {
		if err := tunnel.Start(); err != nil {
			fmt.Printf("[FATAL] Tunnel service failed to start: %v\n", err)
			os.Exit(1)
		}
	}()

	/* Start Web Panel (HTTP-only, Dashboard doesn't need HTTPS). */
	if err := wp.Start(); err != nil {
		fmt.Printf("[FATAL] Dashboard failed to start: %v\n", err)
		os.Exit(1)
	}
}

func generateDefaultConfigs() {
	token := util.GenerateNonce() + util.GenerateNonce() /* 32-char hex string */

	/* Generate ClientID and save to data/client */
	clientID := util.GenerateUUID()
	clientDataDir := filepath.Join("data", "client")
	if _, err := os.Stat(clientDataDir); os.IsNotExist(err) {
		_ = os.MkdirAll(clientDataDir, 0755)
	}
	idFile := filepath.Join(clientDataDir, ".spleen_client_id")
	if err := os.WriteFile(idFile, []byte(clientID), 0600); err != nil {
		fmt.Printf("[WARN] Failed to save ClientID: %v\n", err)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                                SPLEEN TOKEN                               ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Token:    %s  ║\n", token)
	fmt.Printf("║  ClientID: %-59s║\n", clientID)
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
}

func printBanner(panelAddr, tunnelAddr, configPath string, rulesCount int, certExpiry time.Time, https bool) {
	const width = 61 // Inner content width

	fmt.Println()
	fmt.Println("╔═════════════════════════════════════════════════════════════╗")
	fmt.Printf("║%-61s║\n", centerText("Spleen Server v"+Version, width))
	fmt.Println("╠═════════════════════════════════════════════════════════════╣")

	// Dashboard
	dashLabel := "  Dashboard:  "
	if https {
		fmt.Printf("║%-61s║\n", padRight(dashLabel+"https://"+panelAddr, width))
	} else {
		fmt.Printf("║%-61s║\n", padRight(dashLabel+"http://"+panelAddr, width))
	}

	// Tunnel
	fmt.Printf("║%-61s║\n", padRight("  Tunnel:     tls://"+tunnelAddr, width))

	// Config
	fmt.Printf("║%-61s║\n", padRight("  Config:     "+configPath, width))

	fmt.Println("╠═════════════════════════════════════════════════════════════╣")

	// Rules
	if rulesCount > 0 {
		fmt.Printf("║%-61s║\n", padRight(fmt.Sprintf("  Rules:      %d mapping rule(s) loaded", rulesCount), width))
	} else {
		fmt.Printf("║%-61s║\n", padRight("  Rules:      No rules loaded", width))
	}

	// TLS
	fmt.Printf("║%-61s║\n", padRight("  TLS:        Cert valid until "+certExpiry.Format("2006-01-02"), width))

	fmt.Println("╚═════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("[%s] Server started, waiting for clients...\n", time.Now().Format("15:04:05"))
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

func centerText(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	leftPad := (width - len(s)) / 2
	rightPad := width - len(s) - leftPad
	return strings.Repeat(" ", leftPad) + s + strings.Repeat(" ", rightPad)
}

func loadOrCreateTLSConfig() (*tls.Config, time.Time, error) {
	/* Ensure data directory exists */
	const dataDir = "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		_ = os.Mkdir(dataDir, 0755)
	}

	certFile := filepath.Join(dataDir, ".spleen-server-cert.pem")
	keyFile := filepath.Join(dataDir, ".spleen-server-key.pem")
	var certExpiry time.Time

	/* Check if certificate files exist. */
	if certPEM, err := os.ReadFile(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				/* Parse certificate to get expiry date. */
				if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
					certExpiry = x509Cert.NotAfter
				}
				fmt.Println("[INIT] TLS certificates loaded")
				return &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				}, certExpiry, nil
			}
		}
		_ = certPEM /* Silence unused warning. */
	}

	/* Generate new certificate. */
	fmt.Println("[INIT] Generating new TLS certificates...")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, time.Time{}, err
	}

	certExpiry = time.Now().AddDate(10, 0, 0)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Spleen"},
			CommonName:   "Spleen Tunnel Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              certExpiry,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, time.Time{}, err
	}

	/* Save certificates to files. */
	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to create certificate file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certOut.Close()
		return nil, time.Time{}, fmt.Errorf("failed to write certificate: %w", err)
	}
	certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to create key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		keyOut.Close()
		return nil, time.Time{}, fmt.Errorf("failed to write private key: %w", err)
	}
	keyOut.Close()

	fmt.Println("[INIT] TLS certificates generated successfully")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, time.Time{}, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, certExpiry, nil
}
