package tlsman

import (
	"errors"
	"fmt"

	"github.com/copartner6412/input/validate"
)

// Subject defines the methods required to represent a host for which a TLS certificate will be generated.
type Subject interface {
	GetHTTPSPort() uint16

	GetHTTPSAddresses() []string

	// GetCountry returns the Country for the TLS certificate.
	GetCountry() []string
}

// validateSubject returns a non-nil error if none of the following items is specified: hostname, IPv4 address, IPv6 address, or domain name.
func ValidateSubject(subject Subject) error {
	if subject == nil {
		return errors.New("nil subject")
	}

	port := subject.GetHTTPSPort()
	addresses := subject.GetHTTPSAddresses()
	countries := subject.GetCountry()

	var errs []error

	if port == 0 {
		errs = append(errs, fmt.Errorf("port not specified"))
	}

	if addresses == nil {
		errs = append(errs, fmt.Errorf("no address specified"))
	} else {
		for _, address := range addresses {
			err1 := validate.IP(address, "")
			err2 := validate.Domain(address, 0, 0)
			err3 := validate.LinuxHostname(address, 0, 0)
			if err1 != nil && err2 != nil && err3 != nil {
				errs = append(errs, fmt.Errorf("invalid address \"%s\"", address))
			}
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
