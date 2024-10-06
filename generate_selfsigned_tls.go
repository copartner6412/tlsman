package tlsman

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/copartner6412/input/random"
	"github.com/copartner6412/input/validate"
)

const (
	minSerialNumberBitSize uint          = 128
	maxSerialNumberBitSize uint          = 160
)

func GenerateSelfSignedTLS(certificateTemplate *x509.Certificate, algorithm Algorithm, password string)(TLS, error) {
	if err := validateGenerateSelfSignedTLSInput(certificateTemplate, password); err != nil {
		return TLS{}, fmt.Errorf("invalid input: %w", err)
	}

	publicKey, privateKey, err := random.KeyPair(rand.Reader, random.Algorithm(algorithm))
	if err != nil {
		return TLS{}, fmt.Errorf("error generating crypto key pair: %w", err)
	}

	serialNumber, err := random.BigInteger(rand.Reader, minSerialNumberBitSize, maxSerialNumberBitSize)
	if err != nil {
		return TLS{}, fmt.Errorf("error generating random serial number: %w", err)
	}

	certificateTemplate.SerialNumber = serialNumber

	certificatePEMBytes, err := createCertificatePEMBytes(certificateTemplate, publicKey, certificateTemplate, privateKey)
	if err != nil {
		return TLS{}, fmt.Errorf("error creating PEM-encoded x509 certificate as byte slice: %w", err)
	}

	fullchainPEMBytes := certificatePEMBytes

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
		PrivateKeyPassword: []byte(password),
		NotBefore:          certificateTemplate.NotBefore,
		NotAfter:           certificateTemplate.NotAfter,
	}

	if _, _, _, _, err := result.Parse(); err != nil {
		return TLS{}, fmt.Errorf("generated invalid self-signed TLS: %w", err)
	}

	return result, nil
}


func validateGenerateSelfSignedTLSInput(template *x509.Certificate, password string) error {
	var errs []error

	if err := validateCertificateTemplateTime(template); err != nil {
		errs = append(errs, fmt.Errorf("invalid template: %w", err)) 
	}

	if err := validate.PasswordFor(password, validate.PasswordProfileTLSCAKey); err != nil {
		errs = append(errs, fmt.Errorf("invalid password: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func validateCertificateTemplateTime(template *x509.Certificate) error {
	var errs []error

	if template.NotAfter.Before(time.Now()) {
		errs = append(errs, fmt.Errorf("certificate already expired"))
	}

	if template.NotBefore.After(template.NotAfter) {
		errs = append(errs, fmt.Errorf("certificate end time before start time"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
