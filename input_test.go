package tlsman_test

import (
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/coparter6412/tlsman"
	"github.com/copartner6412/input/pseudorandom"
	"github.com/copartner6412/input/random"
)

const (
	minDuration time.Duration = 1 * time.Second
	maxDuration time.Duration = 50 * 365 * 24 * time.Hour // 30 years
)

type mockSubject struct {
	domain   string
	hostname string
	ipv4     string
	ipv6     string
	country  string
}

func (s mockSubject) GetDomain() []string {
	return []string{s.domain}
}

func (s mockSubject) GetHostname() string {
	return s.hostname
}

func (s mockSubject) GetIPv4() []string {
	return []string{s.ipv4}
}

func (s mockSubject) GetIPv6() []string {
	return []string{"127.0.0.1", s.ipv6}
}

func (s mockSubject) GetCountry() []string {
	return []string{s.country}
}

const (
	minSerialNumberBitSize uint = 128
	maxSerialNumberBitSize uint = 160
)

type generateTLSInput struct {
	subject             mockSubject
	ca                  tlsman.TLS
	organization, email string
	duration            time.Duration
	algorithm           tlsman.Algorithm
	password            string
}

func pseudorandomInputForGenerate(r *rand.Rand) (generateTLSInput, error) {

	var errs []error

	subject, err := pseudorandomSubject(r)
	if err != nil {
		errs = append(errs, err)
	}

	ca, err := pseudorandomCA(r)
	if err != nil {
		errs = append(errs, err)
	}

	organization, err := pseudorandom.Password(r, 5, 64, true, true, true, false)
	if err != nil {
		errs = append(errs, err)
	}

	email, err := pseudorandom.Email(r, 5, 100, false, false)
	if err != nil {
		errs = append(errs, err)
	}

	validDuration, err := pseudorandom.Duration(r, minDuration, maxDuration)
	if err != nil {
		errs = append(errs, err)
	}

	algorithm := pseudorandomAlgorithm(r)

	if algorithm == 5 || algorithm == 8 {
		algorithm = 0
	}

	password, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileTLSKey)
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return generateTLSInput{}, errors.Join(errs...)
	}

	return generateTLSInput{
		subject:      subject,
		ca:           ca,
		organization: organization,
		email:        email,
		duration:     validDuration,
		algorithm:    algorithm,
		password:     password,
	}, nil
}

func pseudorandomSubject(r *rand.Rand) (mockSubject, error) {
	var errs []error

	domain, err := pseudorandom.Domain(r, 0, 0)
	if err != nil {
		errs = append(errs, err)
	}

	hostname, err := pseudorandom.LinuxHostname(r, 0, 0)
	if err != nil {
		errs = append(errs, err)
	}

	ipv4, err := pseudorandom.IPv4(r, "")
	if err != nil {
		errs = append(errs, err)
	}

	ipv6, err := pseudorandom.IPv6(r, "")
	if err != nil {
		errs = append(errs, err)
	}

	country := pseudorandom.CountryCode2(r)

	if len(errs) > 0 {
		return mockSubject{}, errors.Join(errs...)
	}

	return mockSubject{
		domain:   domain,
		hostname: hostname,
		ipv4:     ipv4.String(),
		ipv6:     ipv6.String(),
		country:  country,
	}, nil
}

func pseudorandomCA(r *rand.Rand) (tlsman.TLS, error) {
	var errs []error

	serialNumber, err := pseudorandom.BigInteger(r, minSerialNumberBitSize, maxSerialNumberBitSize)
	if err != nil {
		errs = append(errs, err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}

	caAlgorithm := pseudorandomAlgorithm(r)

	caPublicKey, caPrivateKey, err := random.KeyPair(random.Algorithm(caAlgorithm))
	if err != nil {
		errs = append(errs, err)
	}

	caPassword, err := pseudorandom.PasswordFor(r, pseudorandom.PasswordProfileTLSCAKey)
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return tlsman.TLS{}, fmt.Errorf("error generating valid input for creating a CA: %v", errors.Join(errs...))
	}

	ca, err := tlsman.IssueTLS(tlsman.TLS{}, caPublicKey, caPrivateKey, &caTemplate, caPassword)
	if err != nil {
		return tlsman.TLS{}, fmt.Errorf("error creating a CA: %v", err)
	}

	return ca, nil
}

func pseudorandomAlgorithm(r *rand.Rand) tlsman.Algorithm {
	return tlsman.Algorithm(r.IntN(9))
}
