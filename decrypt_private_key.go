package tlsman

import (
	"bytes"
	"fmt"
)

func DecryptPrivateKeyPEM(privateKeyPEMBytes []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("empty password")
	}

	// Ensure consistent line endings (use LF) and remove any trailing whitespace
	privateKeyPEMBytes = bytes.ReplaceAll(privateKeyPEMBytes, []byte("\r\n"), []byte("\n"))
	privateKeyPEMBytes = bytes.TrimSpace(privateKeyPEMBytes)

	decryptedPrivateKey, err := ParsePrivateKey(privateKeyPEMBytes, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("error parsing the encrypted private key: %w", err)
	}

	if decryptedPrivateKey == nil {
		return nil, fmt.Errorf("nil private key")
	}

	decryptedPrivateKeyPEMBytes, err := encodePrivateKeyToPEM(decryptedPrivateKey, "")
	if err != nil {
		return nil, fmt.Errorf("error PEM-encoding the decrypted private key: %w", err)
	}

	return decryptedPrivateKeyPEMBytes, nil
}
