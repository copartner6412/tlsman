package tlsman

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/copartner6412/input/random"
)

func CreateCertificate(certificateTemplate *x509.Certificate, csr []byte, ca TLS) (certificatePEMBytes, fullchainPEMBytes []byte, err error) {
	if err := validateCreateCertificateInput(ca, csr, certificateTemplate); err != nil {
		return nil, nil, fmt.Errorf("invalid input: %w", err)
	}

	_, caPrivateKey, caCertificate, _, err := ca.Parse()
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing CA TLS assets: %w", err)
	}

	request, err := ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate request: %w", err)
	}

	serialNumber, err := random.BigInteger(rand.Reader, minSerialNumberBitSize, maxSerialNumberBitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random serial number: %w", err)
	}

	certificateTemplate.PublicKey = request.PublicKey
	certificateTemplate.SerialNumber = serialNumber
	certificateTemplate.Subject = request.Subject
	certificateTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	certificateTemplate.Extensions = request.Extensions
	certificateTemplate.ExtraExtensions = request.ExtraExtensions
	certificateTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	certificateTemplate.DNSNames = request.DNSNames
	certificateTemplate.EmailAddresses = request.EmailAddresses
	certificateTemplate.IPAddresses = request.IPAddresses
	certificateTemplate.URIs = request.URIs
	certificateTemplate.AuthorityKeyId = caCertificate.SubjectKeyId

	certificatePEMBytes, err = createCertificatePEMBytes(certificateTemplate, request.PublicKey, caCertificate, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating PEM-encoded byte slice of x509 certificate: %w", err)
	}

	fullchainPEMBytes = append(certificatePEMBytes, ca.Fullchain...)

	return certificatePEMBytes, fullchainPEMBytes, nil
}

func validateCreateCertificateInput(ca TLS, csr []byte, certificateTemplate *x509.Certificate) error {
	var errs []error

	if _, _, _, _, err := ca.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid TLS: %w", err))
	}

	if _, err := ParseCertificateRequest(csr); err != nil {
		errs = append(errs, fmt.Errorf("invalid certificate request: %w", err))
	}

	if err := validateCertificateTemplateTime(certificateTemplate); errs != nil {
		errs = append(errs, fmt.Errorf("invalid x509 certificate template: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// createCertificatePEM generates a PEM-encoded X509 certificate as byte slice using the provided template, public key, CA certificate, and CA private key.
func createCertificatePEMBytes(certificateTemplate *x509.Certificate, publicKey crypto.PublicKey, caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey) ([]byte, error) {
	certificateDERBytes, err := x509.CreateCertificate(rand.Reader, certificateTemplate, caCertificate, publicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating standard DER-encoded x509 certificate as byte slice: %w", err)
	}

	certificatePEMBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certificateDERBytes}

	return pem.EncodeToMemory(certificatePEMBlock), nil
}
