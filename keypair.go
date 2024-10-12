package tlsman

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type KeyPair struct {
	PublicKey          []byte
	PrivateKey         []byte
	PrivateKeyPassword []byte
}

func (k *KeyPair) Destroy() {
	k.PublicKey = nil
	k.PrivateKey = nil
	k.PrivateKeyPassword = nil
}

func (k *KeyPair) IsZero() bool {
	return len(k.PublicKey) == 0 &&
		len(k.PrivateKey) == 0 &&
		len(k.PrivateKeyPassword) == 0
}

func (k *KeyPair) Equal(keyPair KeyPair) bool {
	return bytes.Equal(k.PublicKey, keyPair.PublicKey) &&
		bytes.Equal(k.PrivateKey, keyPair.PrivateKey) &&
		bytes.Equal(k.PrivateKeyPassword, keyPair.PrivateKeyPassword)
}

func (k *KeyPair) Parse() (publicKey crypto.PublicKey, privateKey crypto.PrivateKey, err error) {
	var errs []error

	publicKey, err = parsePublicKey(k.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	privateKey, err = parsePrivateKey(k.PrivateKey, k.PrivateKeyPassword)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
	}

	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	if !arePublicAndPrivateKeysMatched(publicKey, privateKey) {
		return nil, nil, fmt.Errorf("key pair mismatch")
	}

	return publicKey, privateKey, nil
}

func (k *KeyPair) Save(directoryPath string) error {
	if err := validateKeyPairSaveInput(k, directoryPath); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Define files with their attributes.
	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamePublicKey, data: k.PublicKey, permission: os.FileMode(0644)},
		"private key": {filename: filenamePrivateKey, data: k.PrivateKey, permission: os.FileMode(0600)},
	}

	// Write each file.
	var errs []error
	for name, file := range files {
		if err := writeBytesToFile(directoryPath, name, file.filename, file.data, file.permission); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (k *KeyPair) NewTLS(certificatePEMBytes, fullchainBytes []byte) (TLS, error) {
	certificate, err := ParseCertificate(certificatePEMBytes)
	if err != nil {
		return TLS{}, fmt.Errorf("error parsing certificate: %w", err)
	}

	tlsAsset := TLS{
		PublicKey:          k.PublicKey,
		PrivateKey:         k.PrivateKey,
		Certificate:        certificatePEMBytes,
		Fullchain:          fullchainBytes,
		PrivateKeyPassword: k.PrivateKeyPassword,
		NotBefore:          certificate.NotBefore,
		NotAfter:           certificate.NotAfter,
	}

	if _, _, _, _, err := tlsAsset.Parse(); err != nil {
		return TLS{}, fmt.Errorf("invalid new TLS: %w", err)
	}

	return tlsAsset, nil
}


func writeBytesToFile(dir, name, filename string, data []byte, permission os.FileMode) error {
	path := filepath.Join(dir, filename)

	// Ensure consistent line endings (use LF) and remove any trailing whitespace.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.TrimSpace(data)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating directory %s: %w", dir, err)
	}

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

func validateKeyPairSaveInput(k *KeyPair, directoryPath string) error {
	var errs []error

	if _, _, err := k.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid TLS: %w", err))
	}

	if directoryPath == "" {
		errs = append(errs, errors.New("empty path for directory"))
		return errors.Join(errs...)
	}

	if !filepath.IsAbs(directoryPath) {
		errs = append(errs, fmt.Errorf("path to directory \"%s\" is not absolute", directoryPath))
		return errors.Join(errs...)
	}

	return nil
}