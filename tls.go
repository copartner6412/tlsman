package tlsman

import "time"

// TLS encapsulates all relevant TLS data, including keys, certificates, and metadata.
type TLS struct {
	// PEM-encoded public key
	PublicKey []byte

	// PEM-encoded private key
	PrivateKey []byte

	// PEM-encoded TLS certificate
	Certificate []byte

	// full chain of PEM-encoded TLS certificates
	Fullchain []byte

	PrivateKeyPassword string

	// NotAfter field in the parsed TLS certificate
	CertificateExpiresAt time.Time
}

// Destroy clears sensitive data within the TLS struct.
// It should be called when the TLS data is no longer needed to ensure secure disposal.
func (t *TLS) Destroy() {
	t.PrivateKeyPassword = ""
}

// Structs containing []byte cannot be compared. IsZero method is defined to make it possiobe to compare variable of type TLS with TLS zero value (instead of using `== TLS{}`)
func (t *TLS) IsZero() bool {
	return len(t.PublicKey) == 0 &&
		len(t.PrivateKey) == 0 &&
		len(t.Certificate) == 0 &&
		len(t.Fullchain) == 0 &&
		t.PrivateKeyPassword == "" &&
		t.CertificateExpiresAt.IsZero()
}
