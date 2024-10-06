package tlsman

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/copartner6412/input/random"
	"github.com/copartner6412/input/validate"
	googlex509 "github.com/google/certificate-transparency-go/x509"

)

func GenerateKeyPair(randomness io.Reader, algorithm Algorithm, password string) (KeyPair, error) {
	if err := validate.PasswordFor(password, validate.PasswordProfileTLSKey); err != nil {
		return KeyPair{}, fmt.Errorf("invalid password: %w", err)
	}

	publicKey, privateKey, err := random.KeyPair(randomness, random.Algorithm(algorithm))
	if err != nil {
		return KeyPair{}, fmt.Errorf("error generating crypto key pair: %w", err)
	}

	publicKeyPEMBytes, err := encodePublicKeyToPEM(publicKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error PEM-encoding public key: %w", err)
	}

	privateKeyPEMBytes, err := encodePrivateKeyToPEM(privateKey, password)
	if err != nil {
		return KeyPair{}, fmt.Errorf("error PEM-encoding private key: %w", err)
	}

	result := KeyPair{
		PublicKey:          publicKeyPEMBytes,
		PrivateKey:         privateKeyPEMBytes,
		PrivateKeyPassword: []byte(password),
	}

	if _, _, err := result.Parse(); err != nil {
		return KeyPair{}, fmt.Errorf("generated invalid key pair: %w", err)
	}

	return result, nil
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
