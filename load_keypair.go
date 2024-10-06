package tlsman

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func LoadKeyPair(directory, privateKeyPassword string) (KeyPair, error) {
	if directory == "" {
		return KeyPair{}, fmt.Errorf("empty directory path")
	}

	var errs []error

	files := map[string]string{
		"public key":  filenamePublicKey,
		"private key": filenamePrivateKey,
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
		return KeyPair{}, errors.Join(errs...)
	}

	result := KeyPair{
		PublicKey:          fileContents["public key"],
		PrivateKey:         fileContents["private key"],
		PrivateKeyPassword: []byte(privateKeyPassword),
	}

	if _, _, err := result.Parse(); err != nil {
		return KeyPair{}, fmt.Errorf("invalid key pair: %w", err)
	}

	return result, nil
}
