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
	googlex509 "github.com/google/certificate-transparency-go/x509"
)

// Parse extracts the public key, private key, and certificates from the provided TLS struct.
// It returns the parsed components along with any errors encountered during parsing.
func ParseTLS(tls TLS) (publicKey crypto.PublicKey, privateKey crypto.PrivateKey, certificate *x509.Certificate, fullchain []*x509.Certificate, err error) {
	if err := validateParseInput(tls); err != nil {
		return nil, nil, nil, nil, err
	}

	var errs []error

	publicKey, err = parsePublicKey(tls.PublicKey)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing public key: %w", err))
	}

	privateKey, err = parsePrivateKey(tls.PrivateKey, tls.PrivateKeyPassword)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing private key: %w", err))
	}

	certificate, err = parseCertificate(tls.Certificate)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing certificate: %w", err))
	}

	fullchain, err = parseFullchain(tls.Fullchain)
	if err != nil {
		errs = append(errs, fmt.Errorf("error parsing fullchain: %w", err))
	}

	if len(errs) > 0 {
		return nil, nil, nil, nil, err
	}

	return publicKey, privateKey, certificate, fullchain, nil
}

func validateParseInput(tls TLS) error {
	if tls.IsZero() {
		return errors.New("empty TLS struct")
	}

	var errs []error

	if tls.PublicKey == nil {
		errs = append(errs, errors.New("public key byte slice is nil"))
	}

	if tls.PrivateKey == nil {
		errs = append(errs, errors.New("private key byte slice is nil"))
	}

	if tls.Certificate == nil {
		errs = append(errs, errors.New("certificate byte slice is nil"))
	}

	if tls.Fullchain == nil {
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
func parsePrivateKey(privateKeyPEMBytes []byte, password string) (privateKey crypto.PrivateKey, err error) {

	privateKeyPEMBlock, _ := pem.Decode(privateKeyPEMBytes)
	if privateKeyPEMBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded private key byte slice to a PEM block: resulted pointer to decoded private keyPEM block is nil")
	}

	privateKeyDERBytes := privateKeyPEMBlock.Bytes

	if googlex509.IsEncryptedPEMBlock(privateKeyPEMBlock) {
		privateKeyDERBytes, err = googlex509.DecryptPEMBlock(privateKeyPEMBlock, []byte(password))
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
		case *rsa.PrivateKey:
			privateKey = key
		case *ecdsa.PrivateKey:
			privateKey = key
		case ed25519.PrivateKey:
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
func parseCertificate(certificatePEMBytes []byte) (certificate *x509.Certificate, err error) {
	certificatePEMBytes = bytes.TrimSpace(certificatePEMBytes)

	certificatePEMBlock, _ := pem.Decode(certificatePEMBytes)
	if certificatePEMBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded X509 certificate byte slice to a PEM block: resulted pointer to decoded certificate PEM block is nil")
	}

	// Defined for verbosity.
	certificateDERBytes := certificatePEMBlock.Bytes

	certificate, err = x509.ParseCertificate(certificateDERBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing DER-enoced X509 certificate byte slice: %w", err)
	}

	emptyX509Certificate := x509.Certificate{}

	if certificate.Equal(&emptyX509Certificate) {
		return nil, errors.New("failed to parse certificate: parsed certificate is empty")
	}

	return certificate, nil
}

// parseFullchain is a helper function for Parse that parses a PEM-encoded fullchain certificate to a slice of x509.certificate pointers.
func parseFullchain(fullchainPEMBytes []byte) (fullchain []*x509.Certificate, err error) {
	fullchainPEMBytes = bytes.ReplaceAll(fullchainPEMBytes, []byte("\r\n"), []byte("\n"))
	rest := bytes.TrimSpace(fullchainPEMBytes)
	var certificatePEMBlock *pem.Block

	for i := 0; i < 100; i++ {
		certificatePEMBlock, rest = pem.Decode(rest)
		if certificatePEMBlock == nil {
			return nil, fmt.Errorf("failed to decode PEM-encoded X509 fullchain certificate byte slice to a PEM block: resulted pointer to decoded certificate PEM block is nil")
		}

		// Defined for verbosity.
		certificateDERBytes := certificatePEMBlock.Bytes

		certificate, err := x509.ParseCertificate(certificateDERBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing DER-enoced X509 certificate byte slice: %w", err)
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