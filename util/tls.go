package util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

/* Computes SHA256 fingerprint of an X.509 certificate for TOFU verification. */
func GetCertFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}
