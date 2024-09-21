package tlsman

import "errors"

// Constants for invalid input errors.
var (
	ErrInvalidSubject               = errors.New("invalid subject")
	ErrInvalidCA                    = errors.New("invalid TLS struct for CA")
	ErrInvalidTLS                   = errors.New("invalid TLS struct")
	ErrInvalidOrganization          = errors.New("invalid organization name")
	ErrInvalidEmail                 = errors.New("invalid email")
	ErrInvalidDuration              = errors.New("invalid duration")
	ErrInvalidAlgorithm             = errors.New("invalid key generation algorithm")
	ErrInvalidPassword              = errors.New("invalid password")
	ErrEmptyX509CertificateTemplate = errors.New("empty X509 certificate template")
	ErrNilPublicKey                 = errors.New("nil crypto.PublicKey")
	ErrNilPrivateKey                = errors.New("nil crypto.PrivateKey")
)
