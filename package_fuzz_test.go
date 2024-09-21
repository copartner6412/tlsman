package tlsman_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coparter6412/tlsman"
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
		input, err := pseudorandomInputForGenerate(r)
		if err != nil {
			t.Fatal(err)
		}

		generatedTLS, err := tlsman.GenerateTLS(input.subject, input.ca, input.organization, input.email, input.duration, input.algorithm, input.password)
		if err != nil {
			t.Fatal(err)
		}

		tempdir := t.TempDir()

		err = tlsman.SaveTLS(generatedTLS, tempdir)
		if err != nil {
			t.Fatalf("error saving TLS in temporary directory %s: %v", tempdir, err)
		}

		loadedTLS, err := tlsman.LoadTLS(tempdir, input.password)
		if err != nil {
			t.Fatalf("error loading TLS from temporary directory %s: %v", tempdir, err)
		}

		decryptedPrivateKey, err := tlsman.DecryptPrivateKeyPEMBytes(loadedTLS.PrivateKey, input.password)
		if err != nil {
			t.Fatalf("error decrypting the private key: %v", err)
		}

		cert, err := tls.X509KeyPair(loadedTLS.Certificate, decryptedPrivateKey)
		if err != nil {
			t.Fatalf("error parsing PEM-encoded certificate and private key: %v", err)
		}

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.WriteString(w, "Hello, TLS!")
			if err != nil {
				t.Fatalf("error writing to HTTP response writer: %v", err)
			}
		}))

		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		server.StartTLS()
		defer server.Close()

		client := createTLSClient(t, loadedTLS)

		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Failed to perform HTTPS request: %v", err)
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if string(body) != "Hello, TLS!" {
			t.Fatalf("Unexpected response body, got %s", string(body))
		}
	})
}

func createTLSClient(t *testing.T, tlsSet tlsman.TLS) *http.Client {
	t.Helper()

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(tlsSet.Fullchain); !ok {
		t.Fatal("Failed to append CA certificate to cert pool")
	}

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}
