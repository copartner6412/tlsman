package tlsman

import (
	"errors"
	"fmt"

	"github.com/copartner6412/input/validate"
)

// Subject defines the methods required to represent a host for which a TLS certificate will be generated.
type Subject interface {
	// GetDomain returns the domain for the TLS certificate.
	GetDomain() []string

	// GetHostname returns the hostname for the TLS certificate.
	GetHostname() string

	// GetIPv4 returns the IPv4 addresses to be included in the certificate.
	GetIPv4() []string

	// GetIPv6 returns the IPv6 addresses to be included in the certificate.
	GetIPv6() []string

	// GetCountry returns the Country for the TLS certificate.
	GetCountry() []string
}

// validateSubject returns a non-nil error if none of the following items is specified: hostname, IPv4 address, IPv6 address, or domain name.
func ValidateSubject(subject Subject) error {
	if subject == nil {
		return errors.New("nil subject")
	}

	domains := subject.GetDomain()
	hostname := subject.GetHostname()
	ipv4s := subject.GetIPv4()
	ipv6s := subject.GetIPv6()
	countries := subject.GetCountry()

	if subject.GetDomain() == nil && subject.GetHostname() == "" && subject.GetIPv4() == nil && subject.GetIPv6() == nil {
		return errors.New("subject must contain at least one of the following: hostname, IPv4 address, IPv6 address, or domain name")
	}

	var errs []error


	for _, domain := range domains {
		if err := validate.Domain(domain, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("invalid domain name: %w", err))
		}
	}

	if hostname != "" {
		if err := validate.LinuxHostname(hostname, 0, 0); err != nil {
			errs = append(errs, fmt.Errorf("invalid hostname: %w", err))
		}
	}

	for _, ipv4 := range ipv4s {
		if err := validate.IP(ipv4, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid IPv4: %w", err))
		}
	}

	for _, ipv6 := range ipv6s {
		if err := validate.IP(ipv6, ""); err != nil {
			errs = append(errs, fmt.Errorf("invalid IPv6: %w", err))
		}
	}

	for _, country := range countries {
		if err := validate.CountryCode2(country); err != nil {
			errs = append(errs, fmt.Errorf("invalid country: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid subject: %w", errors.Join(errs...))
	}

	return nil
}