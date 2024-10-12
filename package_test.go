package tlsman_test

import (
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/copartner6412/tlsman"
)

// TestGenerateTLSFailsForInvalidSubject
// TestGenerateTLSFailsForInvalidCA
// TestGenerateTLSFailsForInvalidOrganization
// TestGenerateTLSFailsForInvalidEmail
// TestGenerateTLSFailsForInvalidDuration
// TestGenerateTLSFailsForInvalidPassword

func FuzzPackage(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Parallel()

		r := rand.New(rand.NewPCG(seed1, seed2))
		clientInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudorandom test input for client: %v", err)
		}

		serverInput, err := pseudorandomTestInput(r)
		if err != nil {
			t.Fatalf("error generating pseudorandom test input for server: %v", err)
		}

		clientTLSDir := t.TempDir()
		serverTLSDir := t.TempDir()

		generatedClientKeyPair, err := tlsman.GenerateKeyPair(cryptorand.Reader, clientInput.algorithm, clientInput.password)
		if err != nil {
			t.Fatalf("error generating key pair for client: %v", err)
		}

		generatedServerKeyPair, err := tlsman.GenerateKeyPair(cryptorand.Reader, serverInput.algorithm, serverInput.password)
		if err != nil {
			t.Fatalf("error generating key pair for server: %v", err)
		}

		if err := generatedClientKeyPair.Save(clientTLSDir); err != nil {
			t.Fatalf("error saving client key pair: %v", err)
		}

		if err := generatedServerKeyPair.Save(serverTLSDir); err != nil {
			t.Fatalf("error saving server key pair: %v", err)
		}

		clientKeyPair, err := tlsman.LoadKeyPair(clientTLSDir, string(generatedClientKeyPair.PrivateKeyPassword))
		if err != nil {
			t.Fatalf("error loading client key pair: %v", err)
		}

		serverKeyPair, err := tlsman.LoadKeyPair(serverTLSDir, string(generatedServerKeyPair.PrivateKeyPassword))
		if err != nil {
			t.Fatalf("error loading server key pair")
		}


		clientRequestBytes, err := tlsman.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{
			Subject:                  pkix.Name{
				Country:            clientInput.subject.GetCountry(),
				Organization:       []string{clientInput.organization},
				CommonName:         "client tls",
			},
		}, clientKeyPair)
		if err != nil {
			t.Fatalf("error creating certificte request for client: %v", err)
		}

		serverRequestBytes, err := tlsman.GenerateServerCertificateRequest(cryptorand.Reader, serverInput.subject, serverKeyPair, serverInput.organization, serverInput.email)
		if err != nil {
			t.Fatalf("error generating certificate request for server: %v", err)
		}

		clientCA, err := tlsman.GenerateSelfSignedTLS(&x509.Certificate{
			Subject: pkix.Name{
				CommonName: "client ca",
			},
			NotBefore: time.Now(),
			NotAfter: time.Now().Add(time.Hour),
			IsCA: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}, clientInput.algorithm, clientInput.password)
		if err != nil {
			t.Fatalf("error generating client CA: %v", err)
		}

		serverCA, err := tlsman.GenerateSelfSignedTLS(&x509.Certificate{
			Subject: pkix.Name{
				CommonName: "server ca",
			},
			NotBefore: time.Now(),
			NotAfter: time.Now().Add(time.Hour),
			IsCA: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}, clientInput.algorithm, clientInput.password)
		if err != nil {
			t.Fatalf("error generating server CA: %v", err)
		}

		clientCertificatePEMBytes, clientFullchainBytes, err := tlsman.CreateCertificate(&x509.Certificate{
			NotBefore:                   time.Now(),
			NotAfter:                    time.Now().Add(time.Hour),
			KeyUsage:                    x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid:       true,
		}, clientRequestBytes, clientCA)
		if err != nil {
			t.Fatalf("error generating client certificate: %v", err)
		}

		serverCertificatePEMBytes, serverFullchainBytes, err := tlsman.CreateCertificate(&x509.Certificate{
			NotBefore:                   time.Now(),
			NotAfter:                    time.Now().Add(time.Hour),
			KeyUsage:                    x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid:       true,
		}, serverRequestBytes, serverCA)
		if err != nil {
			t.Fatalf("error generating server certificate: %v", err)
		}

		clientTLS, err := clientKeyPair.NewTLS(clientCertificatePEMBytes, clientFullchainBytes)
		if err != nil {
			t.Fatalf("error creating client tls: %v", err)
		}

		serverTLS, err := serverKeyPair.NewTLS(serverCertificatePEMBytes, serverFullchainBytes)
		if err != nil {
			t.Fatalf("error creating server tls: %v", err)
		}

		if err := tlsman.TestMTLS(clientTLS, serverTLS); err != nil {
			t.Fatalf("mTLS faild: %v", err)
		}
	})
}
