package tlsman

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func LoadTLS(directory, privateKeyPassword string) (TLS, error) {
	if directory == "" {
		return TLS{}, fmt.Errorf("directory path is empty")
	}

	var errs []error

	files := map[string]string{
		"public key":  filenamePublicKey,
		"private key": filenamePrivateKey,
		"certificate": filenameCertificate,
		"fullchain":   filenameFullchain,
	}

	fileContents := make(map[string][]byte)

	for name, filename := range files {
		path := filepath.Join(directory, filename)

		file, err := os.Open(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("error opening %s: %w", path, err))
			continue
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("error reading %s file: %w", name, err))
			continue
		}

		// Ensure consistent line endings (use LF) and remove any trailing whitespace.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		data = bytes.TrimSpace(data)

		fileContents[name] = data
	}

	if len(errs) > 0 {
		return TLS{}, errors.Join(errs...)
	}

	certificatePEMBytes := fileContents["certificate"]

	certificate, err := parseCertificate(certificatePEMBytes)
	if err != nil {
		return TLS{}, fmt.Errorf("error parsing certificate: %w", err)
	}

	result := TLS{
		PublicKey:            fileContents["public key"],
		PrivateKey:           fileContents["private key"],
		Certificate:          fileContents["certificate"],
		Fullchain:            fileContents["fullchain"],
		PrivateKeyPassword:   privateKeyPassword,
		CertificateExpiresAt: certificate.NotAfter,
	}

	if _, _, _, _, err := ParseTLS(result); err != nil {
		return TLS{}, fmt.Errorf("%w: %w", ErrInvalidTLS, err)
	}

	return result, nil
}