package tlsman

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

func CreateCertificateRequest(randomness io.Reader, requestTemplate *x509.CertificateRequest, keyPair KeyPair) ([]byte, error) {
	publicKey, privateKey, err := keyPair.Parse()
	if err != nil {
		return nil, fmt.Errorf("error decrypting private key: %w", err)
	}

	requestTemplate.PublicKey = publicKey

	certificateRequestDERBytes, err := x509.CreateCertificateRequest(randomness, requestTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating DER-encoded byte slice for certificate request: %w", err)
	}

	pemBlock := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Bytes:   certificateRequestDERBytes,
	}

	certificateRequestPEMBytes := pem.EncodeToMemory(pemBlock)

	return certificateRequestPEMBytes, nil
}