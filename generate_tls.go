package tlsman

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/copartner6412/input/random"
	"github.com/copartner6412/input/validate"
	googlex509 "github.com/google/certificate-transparency-go/x509"
)

const (
	minDurationAllowed time.Duration = 1 * time.Second
	maxDurationAllowed time.Duration = 50 * 365 * 24 * time.Hour // 30 years
	minOrganizationLength uint = 1
	maxOrganizationLength uint = 64
	minSerialNumberBitSize uint = 128
	maxSerialNumberBitSize uint = 160
)

// This function performs the following steps:
// 1. Validates the input parameters to ensure they are correct and complete.
// 2. Generates a certificate template using the provided subject and organization details. If subject is nil, a CA is generated.
// 3. Creates a public-private key pair based on the specified algorithm.
// 4. If subject is nil and CA is empty, a self-signed CA certificate is generated.
// 5. If a CA is provided, the function generates a certificate signed by the CA.
// 6. PEM-encodes the public key, private key, and certificate, returning them in a TLS struct.

// Generate creates a TLS certificate based on the provided inputs, including a subject, Certificate Authority (CA), an optional organization name, an optional email address, validity duration, key generation algorithm, and an optional password for the private key.
//
// Parameters:
//   - subject: A Subject interface representing the entity for which the certificate is being generated.
//   - ca: A TLS struct representing the Certificate Authority. If it's empty, a self-signed certificate will be created.
//   - organization: The name of the organization to be included in the certificate.
//   - validFor: The duration for which the certificate will be valid.
//   - algorithm: The key generation algorithm to be used (e.g., RSA, ECDSA).
//   - password: An optional passphrase for encrypting the private key in PEM format.
//
// Returns:
//   - A TLS struct containing the PEM-encoded public key, private key, certificate, and fullchain.
//   - An error if any issues occur during the certificate generation or encoding process.
//
// Note: For more control over the certificate issuance process, consider using the tlsman.Issue function instead.
func GenerateTLS(subject Subject, ca TLS, organization, email string, validFor time.Duration, algorithm Algorithm, password string) (TLS, error) {
	if err := validateGenerateTLSInput(subject, ca, organization, email, validFor, algorithm, password); err != nil {
		return TLS{}, fmt.Errorf("invalid input: %w", err)
	}

	serialNumber, err := random.BigInteger(minSerialNumberBitSize, maxSerialNumberBitSize)
	if err != nil {
		return TLS{}, fmt.Errorf("error generating random serial number: %w", err)
	}

	template := createCertificateTemplate(subject, serialNumber, organization, email, validFor)

	publicKey, privateKey, err := random.KeyPair(random.Algorithm(algorithm))
	if err != nil {
		return TLS{}, fmt.Errorf("error generating crypto key pair: %w", err)
	}

	var certificatePEMBytes, fullchainPEMBytes []byte

	_, caPrivateKey, caCertificate, _, err := ParseTLS(ca)
	if err != nil {
		return TLS{}, fmt.Errorf("error parsing CA TLS assets: %w", err)
	}

	certificatePEMBytes, err = createCertificatePEM(template, publicKey, caCertificate, caPrivateKey)
	if err != nil {
		return TLS{}, fmt.Errorf("error creating PEM-encoded x509 certificate as byte slice: %w", err)
	}

	fullchainPEMBytes = append(certificatePEMBytes, ca.Fullchain...)

	publicKeyPEMBytes, err := encodePublicKeyToPEM(publicKey)
	if err != nil {
		return TLS{}, fmt.Errorf("error PEM-encoding public key: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEM(privateKey, password)
	if err != nil {
		return TLS{}, fmt.Errorf("error PEM-encoding private key: %w", err)
	}

	result := TLS{
		PublicKey:            publicKeyPEMBytes,
		PrivateKey:           privateKeyPEMBytes,
		Certificate:          certificatePEMBytes,
		Fullchain:            fullchainPEMBytes,
		PrivateKeyPassword:   password,
		CertificateExpiresAt: time.Now().Add(validFor),
	}

	if _, _, _, _, err := ParseTLS(result); err != nil {
		return TLS{}, fmt.Errorf("%w: %w", ErrInvalidTLS, err)
	}

	return result, nil
}

func validateGenerateTLSInput(subject Subject, ca TLS, organization, email string, validFor time.Duration, algorithm Algorithm, password string) error {
	var errs []error

	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidSubject, err))
	}

	if _, _, _, _, err := ParseTLS(ca); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidTLS, err))
	}

	if err := validate.Duration(validFor, minDurationAllowed, maxDurationAllowed); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidDuration, err))
	}

	if organization != "" {
		if err := validateOrganization(organization); err != nil {
			errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidOrganization, err))
		}
	}

	if email != "" {
		err := validate.Email(email, 0, 0, false, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidEmail, err))
		}
	}

	if err := validateAlgorithm(algorithm, []Algorithm{AlgorithmRSA1024, AlgorithmECDSAP224}); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidAlgorithm, err))
	}

	if password != "" {
		if err := validate.PasswordFor(password, validate.PasswordProfileTLSKey); err != nil {
			errs = append(errs, fmt.Errorf("%w: %w", ErrInvalidPassword, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Each organization name should be a non-empty string.
// While there is no explicit maximum length defined in the X.509 standard for each individual organization name, it is generally advisable to keep it concise to avoid issues with certificate size and readability.
// The organization name should consist of printable ASCII characters. It is common to use letters (a-z, A-Z), digits (0-9), spaces, and certain punctuation marks. Special characters should be avoided unless they are explicitly allowed.
// validateOrganization returns a non-nil error if orgranization string is empty or contains any character other printable ASCII characters.
func validateOrganization(organization string) error {
	err := validate.String(organization, minOrganizationLength, maxOrganizationLength, true)
	if err != nil {
		return fmt.Errorf("invalid organization name \"%s\": %w", organization, err)
	}

	if strings.HasPrefix(organization, "-") {
		return fmt.Errorf("organization name \"%s\" starts with a hyphen", organization)
	}

	return nil
}

// validateAlgorithm returns a non-nil error if the algorithm is a member of weak algorithms.
func validateAlgorithm(algorithm Algorithm, weaks []Algorithm) error {
	for _, weak := range weaks {
		if algorithm == weak {
			return errors.New("weak algorithm")
		}
	}

	if algorithm > 8 {
		return fmt.Errorf("unsupport algorithm type")
	}

	return nil
}

// createCertificateTemplate creates a certificate template for either a subject or a CA (Certificate Authority).
func createCertificateTemplate(subject Subject, serialNumber *big.Int, organization, email string, validFor time.Duration) *x509.Certificate {

	domains := subject.GetDomain()
	hostname := subject.GetHostname()
	ipv4s := subject.GetIPv4()
	ipv6s := subject.GetIPv6()
	countries := subject.GetCountry()

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		IsCA:                  false,
	}

	template.Subject.SerialNumber = serialNumber.String()

	// A cascade to specify the common name (CN) of X509 certificate. Order of importance: domain, hostname, IPv4, IPv6
	if domains != nil {
		template.Subject.CommonName = domains[0]
		template.DNSNames = append(template.DNSNames, domains...)
	} else if hostname != "" {
		template.Subject.CommonName = hostname
	} else if ipv4s != nil {
		template.Subject.CommonName = ipv4s[0]
	} else {
		template.Subject.CommonName = ipv6s[0]
	}

	// Hostname should be added to the DNSName slices.
	if hostname != "" {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	// IPv4 should be added to the IPAddresses slice and its string to DNSNames slice.
	for _, ipv4 := range ipv4s {
		parsedIPv4 := net.ParseIP(ipv4)
		template.IPAddresses = append(template.IPAddresses, parsedIPv4)
		template.DNSNames = append(template.DNSNames, ipv4)
	}

	// IPv6 should be added to the IPAddresses slice and its string to DNSNames slice.
	for _, ipv6 := range ipv6s {
		parsedIPv6 := net.ParseIP(ipv6)
		template.IPAddresses = append(template.IPAddresses, parsedIPv6)
		template.DNSNames = append(template.DNSNames, ipv6)
	}

	template.Subject.Country = countries

	if organization != "" {
		template.Subject.Organization = []string{organization}
	}

	if email != "" {
		template.EmailAddresses = []string{email}
	}

	return template
}

// createCertificatePEM generates a PEM-encoded X509 certificate as byte slice using the provided template, public key, CA certificate, and CA private key.
func createCertificatePEM(template *x509.Certificate, publicKey crypto.PublicKey, caCertificate *x509.Certificate, caPrivateKey crypto.PrivateKey) ([]byte, error) {
	certificateDERBytes, err := x509.CreateCertificate(rand.Reader, template, caCertificate, publicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating standard DER-encoded x509 certificate as byte slice: %w", err)
	}

	certificatePEMBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certificateDERBytes}

	return pem.EncodeToMemory(certificatePEMBlock), nil
}

// encodePublicKeyToPEM encodes a public key into PEM format.
func encodePublicKeyToPEM(publicKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), nil
}

// encodePrivateKeyToPEM encodes a private key into PEM format, encrypting it with a password if provided.
func encodePrivateKeyToPEM(privateKey crypto.PrivateKey, password string) ([]byte, error) {
	var privateKeyPEMBlock *pem.Block

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyPEMBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *ecdsa.PrivateKey:
		privateKeyDERBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ECDSA private key: %w", err)
		}
		privateKeyPEMBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDERBytes}
	case ed25519.PrivateKey:
		marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ED25519 private key: %w", err)
		}
		privateKeyPEMBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: marshaledKey}
	default:
		return nil, errors.New("unsupported private key type")
	}

	if password != "" {
		privateKeyPEMBlock, err := googlex509.EncryptPEMBlock(rand.Reader, privateKeyPEMBlock.Type, privateKeyPEMBlock.Bytes, []byte(password), googlex509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("error encrypting private key PEM block: %w", err)
		}
		return pem.EncodeToMemory(privateKeyPEMBlock), nil
	}

	return pem.EncodeToMemory(privateKeyPEMBlock), nil
}
