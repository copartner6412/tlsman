package tlsman

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParseCertificateRequest(certificateRequestPEMBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(certificateRequestPEMBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM-encoded certificate request")
	}

	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate request: %w", err)
	}

	return request, nil
}
