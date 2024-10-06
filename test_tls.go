package tlsman

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

func TestMTLS(clientTLS, serverTLS TLS) error {
	decryptedPrivateKey, err := DecryptPrivateKeyPEMBytes(serverTLS.PrivateKey, string(serverTLS.PrivateKeyPassword))
	if err != nil {
		return fmt.Errorf("error decrypting the private key: %w", err)
	}

	cert, err := tls.X509KeyPair(serverTLS.Certificate, decryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("error parsing PEM-encoded certificate and private key: %w", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "Hello, TLS!")
		if err != nil {
			return
		}
	}))

	clientCertPool := x509.NewCertPool()
	if ok := clientCertPool.AppendCertsFromPEM(clientTLS.Fullchain); !ok {
		return fmt.Errorf("error appending CA certificate to client cert pool")
	}

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs: clientCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server.StartTLS()
	defer server.Close()

	client, err := createTLSClient(clientTLS, serverTLS)
	if err != nil {
		return fmt.Errorf("error creating HTTP client: %w", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error performing HTTPS request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	if string(body) != "Hello, TLS!" {
		return fmt.Errorf("unexpected response body, got %s", string(body))
	}

	return nil
}

func createTLSClient(clientTLS, serverTLS TLS) (*http.Client, error) {
	decryptedPrivateKey, err := DecryptPrivateKeyPEMBytes(clientTLS.PrivateKey, string(clientTLS.PrivateKeyPassword))
	if err != nil {
		return nil, fmt.Errorf("error decrypting the private key: %w", err)
	}

	cert, err := tls.X509KeyPair(clientTLS.Certificate, decryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing PEM-encoded certificate and private key: %w", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(serverTLS.Fullchain); !ok {
		return nil, fmt.Errorf("error appending server CA certificate to cert pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs: certPool,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}