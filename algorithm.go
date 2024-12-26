package tlsman

// Algorithm specifies the key generation algorithms.
type Algorithm int

// List of supported algorithms for key generation.
const (
	// Untyped key algorithm
	AlgorithmUntyped Algorithm = iota

	// ED25519 algorithm for key generation
	AlgorithmED25519

	// ECDSA algorithm with P-521 elliptic curve for key generation
	AlgorithmECDSAP521

	// ECDSA algorithm with P-384 elliptic curve for key generation
	AlgorithmECDSAP384

	// ECDSA algorithm with P-256 elliptic curve for key generation
	AlgorithmECDSAP256

	// ECDSA algorithm with P224 elliptic curve for key generation
	AlgorithmECDSAP224

	// RSA algorithm with 4096-bit key for key generation
	AlgorithmRSA4096

	// RSA algorithm with 2048-bit key for key generation
	AlgorithmRSA2048

	// RSA algorithm with 1024-bit key for key generation
	AlgorithmRSA1024
)

var algorithmString = map[Algorithm]string{
	AlgorithmUntyped:   "untyped",
	AlgorithmED25519:   "ED25519",
	AlgorithmECDSAP521: "ECDSA-P521",
	AlgorithmECDSAP384: "ECDSA-P384",
	AlgorithmECDSAP256: "ECDSA-P256",
	AlgorithmECDSAP224: "ECDSA-P224",
	AlgorithmRSA4096:   "RSA-4096",
	AlgorithmRSA2048:   "RSA-2048",
	AlgorithmRSA1024:   "RSA-1024",
}

func (a Algorithm) String() string {
	return algorithmString[a]
}
