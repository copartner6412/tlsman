package tlsman_test

import (
	"errors"
	"math/rand/v2"
	"time"

	"github.com/copartner6412/tlsman"
	"github.com/copartner6412/input/pseudorandom"
)

const (
	minDuration time.Duration = 1 * time.Second
	maxDuration time.Duration = 50 * 365 * 24 * time.Hour // 30 years
)

type mockSubject struct {
	port     uint16
	domain   string
	hostname string
	ipv4     string
	ipv6     string
	country  string
}

func (s mockSubject) GetHTTPSPort() uint16 {
	return s.port
}

func (s mockSubject) GetHTTPSAddresses() []string {
	return []string{"127.0.0.1", s.ipv6}
}

func (s mockSubject) GetCountry() []string {
	return []string{s.country}
}

const (
	minSerialNumberBitSize uint = 128
	maxSerialNumberBitSize uint = 160
)

type testInput struct {
	subject             mockSubject
	organization, email string
	duration            time.Duration
	algorithm           tlsman.Algorithm
	password            string
}

func pseudorandomTestInput(r *rand.Rand) (testInput, error) {

	var errs []error

	subject, err := pseudorandomSubject(r)
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
		return testInput{}, errors.Join(errs...)
	}

	return testInput{
		subject:      subject,
		organization: organization,
		email:        email,
		duration:     validDuration,
		algorithm:    algorithm,
		password:     password,
	}, nil
}

func pseudorandomSubject(r *rand.Rand) (mockSubject, error) {
	port := pseudorandom.PortPrivate(r)

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
		port:     port,
		domain:   domain,
		hostname: hostname,
		ipv4:     ipv4.String(),
		ipv6:     ipv6.String(),
		country:  country,
	}, nil
}

func pseudorandomAlgorithm(r *rand.Rand) tlsman.Algorithm {
	return tlsman.Algorithm(r.IntN(9))
}
