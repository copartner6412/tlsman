package tlsman

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// The function performs the following steps:
//   1. Validates the input parameters to ensure they are correct and complete.
//   2. If the CA is zero (indicating a self-signed certificate), it creates a self-signed certificate using the provided template and keys.
//   3. If a CA is provided, it parses the CA's private key and certificate, then generates a certificate signed by the CA.
//   4. The function encodes the public key, private key, and certificate into PEM format and returns them as part of a TLS struct.

// Issue generates a TLS certificate based on the provided template and keys, signing it with the specified Certificate Authority (CA) if provided.
//
// Parameters:
//   - ca: A TLS struct representing the Certificate Authority. If empty, a self-signed certificate will be generated.
//   - template: A pointer to an x509.Certificate template that defines the properties of the certificate to be issued.
//   - publicKey: The public key associated with the certificate being generated.
//   - privateKey: The private key used to sign the certificate.
//   - password: An optional passphrase for encrypting the private key in PEM format.
//
// Returns:
//   - A TLS struct containing the PEM-encoded public key, private key, certificate, and fullchain.
//   - An error if any issues occur during the certificate generation or encoding process.
func IssueTLS(ca TLS, publicKey crypto.PublicKey, privateKey crypto.PrivateKey, template *x509.Certificate, password string) (TLS, error) {
	var err error

	if err := validateIssueInput(ca, publicKey, privateKey); err != nil {
		return TLS{}, fmt.Errorf("invalid input: %w", err)
	}

	var certificatePEMBytes, fullchainPEMBytes []byte

	if ca.IsZero() { // Self-signed CA certificate
		certificatePEMBytes, err = createCertificatePEM(template, publicKey, template, privateKey)
		if err != nil {
			return TLS{}, fmt.Errorf("error creating PEM-encoded self-signed x509 certificate as byte slice: %w", err)
		}

		fullchainPEMBytes = certificatePEMBytes
	} else { // CA-signed certificate
		_, caPrivateKey, caCertificate, _, err := ParseTLS(ca)
		if err != nil {
			return TLS{}, fmt.Errorf("error parsing CA TLS assets: %w", err)
		}

		certificatePEMBytes, err = createCertificatePEM(template, publicKey, caCertificate, caPrivateKey)
		if err != nil {
			return TLS{}, fmt.Errorf("error creating PEM-encoded x509 certificate as byte slice: %w", err)
		}

		fullchainPEMBytes = append(certificatePEMBytes, ca.Fullchain...)
	}

	publicKeyPEMBytes, err := encodePublicKeyToPEM(publicKey)
	if err != nil {
		return TLS{}, fmt.Errorf("error PEM-encoding public key: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEM(privateKey, password)
	if err != nil {
		return TLS{}, fmt.Errorf("error PEM-encoding private key: %w", err)
	}

	result := TLS{
		PublicKey:          publicKeyPEMBytes,
		PrivateKey:         privateKeyPEMBytes,
		Certificate:        certificatePEMBytes,
		Fullchain:          fullchainPEMBytes,
		PrivateKeyPassword: password,
		NotBefore:          time.Now().Add(time.Until(template.NotBefore)),
		NotAfter:           time.Now().Add(time.Until(template.NotAfter)),
	}

	if _, _, _, _, err := ParseTLS(result); err != nil {
		return TLS{}, fmt.Errorf("%w: %w", ErrInvalidTLS, err)
	}

	return result, nil
}

func validateIssueInput(ca TLS, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) error {
	var errs []error

	if !ca.IsZero() {
		if _, _, _, _, err := ParseTLS(ca); err != nil {
			errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidCA, err))
		}
	}

	if publicKey == nil {
		errs = append(errs, ErrNilPublicKey)
	}

	if privateKey == nil {
		errs = append(errs, ErrNilPrivateKey)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
