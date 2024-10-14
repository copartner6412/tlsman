package tlsman

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	googlex509 "github.com/google/certificate-transparency-go/x509"
)

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

	PrivateKeyPassword []byte

	NotBefore time.Time

	// NotAfter field in the parsed TLS certificate
	NotAfter time.Time
}

const (
	filenamePublicKey   string = "pub.pem"
	filenamePrivateKey  string = "key.pem"
	filenameCertificate string = "cert.pem"
	filenameFullchain   string = "full.pem"
)

// Destroy clears sensitive data within the TLS struct.
// It should be called when the TLS data is no longer needed to ensure secure disposal.
func (t *TLS) Destroy() {
	t.PublicKey = nil
	t.PrivateKey = nil
	t.Certificate = nil
	t.Fullchain = nil
	t.PrivateKeyPassword = nil
	t.NotBefore = time.Time{}
	t.NotAfter = time.Time{}
}

// Structs containing []byte cannot be compared. IsZero method is defined to make it possible to compare variable of type TLS with TLS zero value (instead of using `== TLS{}`)
func (t *TLS) IsZero() bool {
	return len(t.PublicKey) == 0 &&
		len(t.PrivateKey) == 0 &&
		len(t.Certificate) == 0 &&
		len(t.Fullchain) == 0 &&
		len(t.PrivateKeyPassword) == 0 &&
		t.NotBefore.IsZero() &&
		t.NotAfter.IsZero()
}

func (t *TLS) Equal(tlsAsset TLS) bool {
	return bytes.Equal(t.PublicKey, tlsAsset.PublicKey) &&
		bytes.Equal(t.PrivateKey, tlsAsset.PrivateKey) &&
		bytes.Equal(t.PrivateKeyPassword, tlsAsset.PrivateKeyPassword) &&
		bytes.Equal(t.Certificate, tlsAsset.Certificate) &&
		bytes.Equal(t.Fullchain, tlsAsset.Fullchain) &&
		t.NotBefore.Equal(tlsAsset.NotBefore) &&
		t.NotAfter.Equal(tlsAsset.NotAfter)
}

func (t *TLS) Parse() (publicKey crypto.PublicKey, privateKey crypto.PrivateKey, certificate *x509.Certificate, fullchain []*x509.Certificate, err error) {
	if err := tlsNotZero(t); err != nil {
		return nil, nil, nil, nil, err
	}

	var errs []error

	publicKey, err = parsePublicKey(t.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	privateKey, err = ParsePrivateKey(t.PrivateKey, t.PrivateKeyPassword)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
	}

	certificate, err = ParseCertificate(t.Certificate)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing certificate: %w", err))
	}

	fullchain, err = ParseFullchain(t.Fullchain)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing fullchain: %w", err))
	}

	if len(errs) > 0 {
		return nil, nil, nil, nil, errors.Join(errs...)
	}

	if !arePublicAndPrivateKeysMatched(publicKey, privateKey) {
		return nil, nil, nil, nil, fmt.Errorf("key pair mismatch")
	}

	return publicKey, privateKey, certificate, fullchain, nil
}

func tlsNotZero(t *TLS) error {
	if t.IsZero() {
		return errors.New("empty TLS")
	}

	var errs []error

	if t.PublicKey == nil {
		errs = append(errs, errors.New("public key byte slice is nil"))
	}

	if t.PrivateKey == nil {
		errs = append(errs, errors.New("private key byte slice is nil"))
	}

	if t.Certificate == nil {
		errs = append(errs, errors.New("certificate byte slice is nil"))
	}

	if t.Fullchain == nil {
		errs = append(errs, errors.New("fullchain byte slice is nil"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// parsePublicKey is a helper function for Parse that parses PEM-encoded public key as byte slice and returns it as crypto.PublicKey type.
func parsePublicKey(publicKeyPEMBytes []byte) (publicKey crypto.PublicKey, err error) {
	publicKeyPEMBlock, _ := pem.Decode(publicKeyPEMBytes)
	if publicKeyPEMBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded public key byte slice to a PEM block: resulted pointer to decoded public key PEM block is nil")
	}

	// Defined this variable for verbosity.
	publicKeyDERBytes := publicKeyPEMBlock.Bytes

	// parses ASN.1 DER-encoded public key byte slice and results crypto.PublicKey.
	publicKey, err = x509.ParsePKIXPublicKey(publicKeyDERBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing DER-encoded public key byte slice as crypto.PublicKey: %w", err)
	}

	if publicKey == nil {
		return nil, errors.New("failed to parse public key: parsed public key is nil")
	}

	return publicKey, nil
}

// parsePrivateKey is a helper function for Parse that parses PEM-encoded private key byte slice and returns it as crypto.Private type.
func ParsePrivateKey(privateKeyPEMBytes, password []byte) (privateKey crypto.PrivateKey, err error) {

	privateKeyPEMBlock, _ := pem.Decode(privateKeyPEMBytes)
	if privateKeyPEMBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded private key byte slice to a PEM block: resulted pointer to decoded private keyPEM block is nil")
	}

	privateKeyDERBytes := privateKeyPEMBlock.Bytes

	if googlex509.IsEncryptedPEMBlock(privateKeyPEMBlock) {
		privateKeyDERBytes, err = googlex509.DecryptPEMBlock(privateKeyPEMBlock, password)
		if err != nil {
			return nil, fmt.Errorf("error decrypting private key PEM block using the provided password: %w", err)
		}
	}

	switch privateKeyPEMBlock.Type {
	case "RSA PRIVATE KEY":
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privateKeyDERBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS #1 DER-encoded RSA private key: %w", err)
		}

		privateKey = rsaPrivateKey
	case "EC PRIVATE KEY":
		ecdsaPrivateKey, err := x509.ParseECPrivateKey(privateKeyDERBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing DER-encoded EC private key: %w", err)
		}

		privateKey = ecdsaPrivateKey
	case "PRIVATE KEY":
		parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDERBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing PKCS #8 DER-encoded [usually ED25519] private key: %w", err)
		}

		switch key := parsedPrivateKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			privateKey = key
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", parsedPrivateKey)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", privateKeyPEMBlock.Type)
	}

	if privateKey == nil {
		return nil, errors.New("failed to parse private key: parsed private key is nil")
	}

	return privateKey, nil
}

// parseCertificate is a helper function for Parse that parses a PEM-encoded certificate byte slice to a x509.certificate pointer.
func ParseCertificate(certificatePEMBytes []byte) (certificate *x509.Certificate, err error) {
	certificatePEMBytes = bytes.TrimSpace(certificatePEMBytes)

	certificatePEMBlock, _ := pem.Decode(certificatePEMBytes)
	if certificatePEMBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded X509 certificate byte slice to a PEM block: resulted pointer to decoded certificate PEM block is nil")
	}

	// Defined for verbosity.
	certificateDERBytes := certificatePEMBlock.Bytes

	certificate, err = x509.ParseCertificate(certificateDERBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing DER-encoded X509 certificate byte slice: %w", err)
	}

	emptyX509Certificate := x509.Certificate{}

	if certificate.Equal(&emptyX509Certificate) {
		return nil, errors.New("failed to parse certificate: parsed certificate is empty")
	}

	return certificate, nil
}

// parseFullchain is a helper function for Parse that parses a PEM-encoded fullchain certificate to a slice of x509.certificate pointers.
func ParseFullchain(fullchainPEMBytes []byte) (fullchain []*x509.Certificate, err error) {
	fullchainPEMBytes = bytes.ReplaceAll(fullchainPEMBytes, []byte("\r\n"), []byte("\n"))
	rest := bytes.TrimSpace(fullchainPEMBytes)
	var certificatePEMBlock *pem.Block

	for i := 0; i < 10; i++ {
		certificatePEMBlock, rest = pem.Decode(rest)
		if certificatePEMBlock == nil {
			return nil, fmt.Errorf("failed to decode PEM-encoded X509 fullchain certificate byte slice to a PEM block: resulted pointer to decoded certificate PEM block is nil")
		}

		// Defined for verbosity.
		certificateDERBytes := certificatePEMBlock.Bytes

		certificate, err := x509.ParseCertificate(certificateDERBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing DER-encoded X509 certificate byte slice: %w", err)
		}

		emptyX509Certificate := x509.Certificate{}

		if certificate.Equal(&emptyX509Certificate) {
			return nil, errors.New("failed to parse certificate: parsed certificate is empty")
		}

		fullchain = append(fullchain, certificate)

		rest = bytes.TrimSpace(rest)

		if rest == nil {
			break
		} else {
			continue
		}

	}

	return fullchain, nil
}

func arePublicAndPrivateKeysMatched(publicKey crypto.PublicKey, privateKey crypto.PrivateKey) bool {
	switch privateKeyTypeAsserted := privateKey.(type) {
	case *rsa.PrivateKey:
		return privateKeyTypeAsserted.PublicKey.Equal(publicKey.(*rsa.PublicKey))
	case *ecdsa.PrivateKey:
		return privateKeyTypeAsserted.PublicKey.Equal(publicKey.(*ecdsa.PublicKey))
	case ed25519.PrivateKey:
		return privateKeyTypeAsserted.Public().(ed25519.PublicKey).Equal(publicKey.(ed25519.PublicKey))
	default:
		return false
	}
}

func (t *TLS) Save(directoryPath string) error {
	if err := validateTLSSaveInput(t, directoryPath); err != nil {
		return fmt.Errorf("invalid input: %w", err)
	}

	// Define files with their attributes.
	files := map[string]struct {
		filename   string
		data       []byte
		permission os.FileMode
	}{
		"public key":  {filename: filenamePublicKey, data: t.PublicKey, permission: os.FileMode(0644)},
		"private key": {filename: filenamePrivateKey, data: t.PrivateKey, permission: os.FileMode(0600)},
		"certificate": {filename: filenameCertificate, data: t.Certificate, permission: os.FileMode(0644)},
		"fullchain":   {filename: filenameFullchain, data: t.Fullchain, permission: os.FileMode(0644)},
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

func validateTLSSaveInput(t *TLS, directoryPath string) error {
	var errs []error

	if _, _, _, _, err := t.Parse(); err != nil {
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
