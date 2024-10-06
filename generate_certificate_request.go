package tlsman

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/copartner6412/input/validate"
)

const (
	minOrganizationLength  uint          = 1
	maxOrganizationLength  uint          = 64
)

func GenerateServerCertificateRequest(randomness io.Reader, subject Subject, keyPair KeyPair, organization, email string) ([]byte, error) {
	if err := validateGenerateCertificateRequestInput(subject, keyPair, organization, email); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	addresses := subject.GetHTTPSAddresses()
	countries := subject.GetCountry()

	var domains, ipv4s, ipv6s []string
	var hostname string

	for _, address := range addresses {
		if err := validate.IP(address, ""); err == nil {
			ip := net.ParseIP(address)
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip.To4().String())
			} else {
				ipv6s = append(ipv6s, ip.To16().String())
			}
		} else if err := validate.LinuxHostname(address, 0, 0); err == nil {
			hostname = address
		} else if err := validate.Domain(address, 0, 0); err == nil {
			domains = append(domains, address)
		}
	}

	request := &x509.CertificateRequest{
		PublicKey:                keyPair.PublicKey,
	}

	if domains != nil {
		request.Subject.CommonName = domains[0]
		request.DNSNames = append(request.DNSNames, domains...)
	} else if hostname != "" {
		request.Subject.CommonName = hostname
	} else if ipv4s != nil {
		request.Subject.CommonName = ipv4s[0]
	} else {
		request.Subject.CommonName = ipv6s[0]
	}

	if hostname != "" {
		request.DNSNames = append(request.DNSNames, hostname)
	}

	for _, ipv4 := range ipv4s {
		parsedIPv4 := net.ParseIP(ipv4)
		request.IPAddresses = append(request.IPAddresses, parsedIPv4)
		request.DNSNames = append(request.DNSNames, ipv4)
	}

	for _, ipv6 := range ipv6s {
		parsedIPv6 := net.ParseIP(ipv6)
		request.IPAddresses = append(request.IPAddresses, parsedIPv6)
		request.DNSNames = append(request.DNSNames, ipv6)
	}

	request.Subject.Country = countries

	if organization != "" {
		request.Subject.Organization = []string{organization}
	}

	if email != "" {
		request.EmailAddresses = []string{email}
	}

	privateKeyBytes, err := DecryptPrivateKeyPEMBytes(keyPair.PrivateKey, string(keyPair.PrivateKeyPassword))
	if err != nil {
		return nil, fmt.Errorf("error decrypting private key: %w", err)
	}

	privateKey, err := parsePrivateKey(privateKeyBytes, keyPair.PrivateKeyPassword)
	if err != nil {
		return nil, fmt.Errorf("error parsing decrypted private key: %w", err)
	}

	certificateRequestDERBytes, err := x509.CreateCertificateRequest(randomness, request, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating DER-encoded byte slice for certificate request: %w", err)
	}

	pemBlock := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Bytes:   certificateRequestDERBytes,
	}

	certificateRequestPEMBytes := pem.EncodeToMemory(pemBlock)

	return certificateRequestPEMBytes, nil
}

func validateGenerateCertificateRequestInput(subject Subject, keyPair KeyPair, organization, email string) error {
	var errs []error
	
	if err := ValidateSubject(subject); err != nil {
		errs = append(errs, fmt.Errorf("invalid subject: %w", err))
	}

	if _, _, err := keyPair.Parse(); err != nil {
		errs = append(errs, fmt.Errorf("invalid key pair: %w", err))
	}

	if organization != "" {
		if err := validateOrganization(organization); err != nil {
			errs = append(errs, fmt.Errorf("invalid organization name %s: %w", organization, err))
		}
	}

	if email != "" {
		err := validate.Email(email, 0, 0, false, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid E-mail %s: %w", email, err))
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
		return err
	}

	if strings.HasPrefix(organization, "-") {
		return fmt.Errorf("organization name \"%s\" starts with a hyphen", organization)
	}

	return nil
}