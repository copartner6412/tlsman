package tlsman

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Constants for default file names of saved TLS assets.
const (
	filenamePublicKey   string = "pub.pem"
	filenamePrivateKey  string = "key.pem"
	filenameCertificate string = "cert.pem"
	filenameFullchain   string = "full.pem"
)

func SaveTLS(tls TLS, directory string) error {
	if err := validateSaveInput(tls, directory); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Define files with their attributes.
	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamePublicKey, data: tls.PublicKey, permission: os.FileMode(0644)},
		"private key": {filename: filenamePrivateKey, data: tls.PrivateKey, permission: os.FileMode(0600)},
		"certificate": {filename: filenameCertificate, data: tls.Certificate, permission: os.FileMode(0644)},
		"fullchain":   {filename: filenameFullchain, data: tls.Fullchain, permission: os.FileMode(0644)},
	}

	// Write each file.
	var errs []error
	for name, file := range files {
		if err := writeBytesToFile(directory, name, file.filename, file.data, file.permission); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateSaveInput(tls TLS, directory string) error {
	var errs []error
	if directory == "" {
		errs = append(errs, fmt.Errorf("empty directory path"))
	}

	if _, _, _, _, err := ParseTLS(tls); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidTLS, err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func writeBytesToFile(dir, name, filename string, data []byte, permission os.FileMode) error {
	path := filepath.Join(dir, filename)

	// Ensure consistent line endings (use LF) and remove any trailing whitespace.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimSpace(data)

	// Open file with O_SYNC flag
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, permission)
	if err != nil {
		return fmt.Errorf("error opening %s for writing: %w", name, err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("error writing %s: %w", name, err)
	}

	return nil
}
