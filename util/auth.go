package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

/* Authentication message sent by clients to establish tunnel connection. */
type AuthMessage struct {
	ClientID   string `json:"client_id"`
	Type       string `json:"type"` /* "tunnel", "ping" */
	Version    string `json:"version"`
	PoolSize   int    `json:"pool_size"`
	TokenProof string `json:"token_proof"`
}

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

/* Returns canonical lowercase UUID text. */
func NormalizeUUID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

/* Validates whether the string is a valid UUID format. */
func IsValidUUID(s string) bool {
	return uuidRegex.MatchString(NormalizeUUID(s))
}

/* Creates HMAC proof: HMAC-SHA256(token, clientID + type + nonce). */
func BuildTokenProof(token, clientID, msgType, nonce string) string {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(clientID + msgType + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

/* Verifies the HMAC proof against stored token hash using constant-time comparison. */
func VerifyTokenProof(storedToken, clientID, msgType, nonce, proof string) bool {
	h := hmac.New(sha256.New, []byte(storedToken))
	h.Write([]byte(clientID + msgType + nonce))
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(proof))
}

/* Generates a random 16-byte hex nonce for challenge-response authentication. */
func GenerateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

/* Generates a random UUID v4 string. */
func GenerateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 /* version 4 */
	b[8] = (b[8] & 0x3f) | 0x80 /* variant */
	return hex.EncodeToString(b[0:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}
