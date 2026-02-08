package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leviathan0992/spleen/util"
)

const Version = "1.0.0"

func main() {
	configPath := flag.String("d", "client-config.json", "Path to configuration file")
	version := flag.Bool("version", false, "Show version information")

	/* Flags for Quick-Join mode */
	serverFlag := flag.String("server", "", "Server address (e.g. 1.2.3.4:5432)")
	tokenFlag := flag.String("token", "", "Authentication Token")

	flag.Parse()

	if *version {
		fmt.Printf("spleen-client version %s\n", Version)
		return
	}

	/* Load config or use flags */
	var serverAddr, clientID, token string
	var poolSize int
	var err error

	/* If using Quick-Join mode (flags present). */
	if *serverFlag != "" && *tokenFlag != "" {
		serverAddr = *serverFlag
		token = *tokenFlag
		poolSize = 128
	} else {
		/* Load from config file. */
		serverAddr, clientID, token, poolSize, err = LoadClientConfig(*configPath)
		if err != nil {
			fmt.Printf("[FATAL] Failed to load configuration: %v\n", err)
			fmt.Println()
			fmt.Println("Please create a configuration file or use Quick-Join mode:")
			fmt.Println("  ./spleen-client -server <IP:Port> -token <Secret>")
			fmt.Println()
			os.Exit(1)
		}
	}

	/* Fallback: If ClientID is still empty, generate or load from data/ */
	if clientID == "" {
		var idErr error
		clientID, idErr = getOrGenerateClientID()
		if idErr != nil {
			fmt.Printf("[WARN] Failed to persist ClientID: %v\n", idErr)
			clientID = util.GenerateUUID()
		}
	}

	clientID = util.NormalizeUUID(clientID)
	if !util.IsValidUUID(clientID) {
		fmt.Println("[FATAL] Invalid client_id: not a valid UUID")
		os.Exit(1)
	}

	/* Ensure ClientID is persisted to data directory for easy access */
	saveClientID(clientID)

	/* Print startup banner. */
	printBanner(serverAddr, clientID, *configPath, poolSize)

	client := NewTunnelClient(serverAddr, clientID, token, poolSize)
	client.Run()
}

func getOrGenerateClientID() (string, error) {
	/* Ensure data directory exists */
	const dataDir = "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		_ = os.Mkdir(dataDir, 0755)
	}

	idFile := filepath.Join(dataDir, ".spleen_client_id")
	if data, err := os.ReadFile(idFile); err == nil {
		id := util.NormalizeUUID(string(data))
		if util.IsValidUUID(id) {
			return id, nil
		}
	}

	id := util.NormalizeUUID(util.GenerateUUID())
	if err := os.WriteFile(idFile, []byte(id), 0600); err != nil {
		return id, err
	}
	return id, nil
}

func printBanner(serverAddr, clientID, configPath string, poolSize int) {
	fmt.Println()
	fmt.Println("╔═════════════════════════════════════════════════════════════╗")
	fmt.Printf("║               Spleen Client v%-30s║\n", Version)
	fmt.Println("╠═════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Server:     %-48s║\n", serverAddr)
	short := clientID
	if len(short) > 8 {
		short = short[:8]
	}
	fmt.Printf("║  ClientID:   %s...%-36s║\n", strings.ToUpper(short), "")
	fmt.Printf("║  Config:     %-48s║\n", configPath)
	fmt.Printf("║  Pool Size:  %-48d║\n", poolSize)
	fmt.Println("╚═════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("[%s] Connecting to tunnel server...\n", time.Now().Format("15:04:05"))
}

func saveClientID(id string) {
	/* Ensure data directory exists */
	const dataDir = "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		_ = os.Mkdir(dataDir, 0755)
	}
	idFile := filepath.Join(dataDir, ".spleen_client_id")
	_ = os.WriteFile(idFile, []byte(id+"\n"), 0600)
}
