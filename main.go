package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	directoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	email        = "i_dont@care.com"
)

var (
	accountKey *ecdsa.PrivateKey
	certKey    *ecdsa.PrivateKey
	nonce      string
	kid        string
	httpServer *http.Server
)

func main() {
	fmt.Printf("Tiny ACME Client\n")
	fmt.Printf("Believe it or not, it works!\n")
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <domain>\n", os.Args[0])
		return
	}
	domain := os.Args[1]
	var err error
	accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate account key: %v\n", err)
		return
	}
	certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate cert key: %v\n", err)
		return
	}
	dir, err := getDirectory()
	if err != nil {
		fmt.Printf("Failed to get directory: %v\n", err)
		return
	}
	err = getNonce(dir.NewNonce)
	if err != nil {
		fmt.Printf("Failed to get nonce: %v\n", err)
		return
	}
	accountURL, err := createAccount(dir.NewAccount)
	if err != nil {
		fmt.Printf("Failed to create account: %v\n", err)
		return
	}
	kid = accountURL
	order, orderURL, err := createOrder(dir.NewOrder, domain)
	if err != nil {
		fmt.Printf("Failed to create order: %v\n", err)
		return
	}
	for _, authzURL := range order.Authorizations {
		err = processAuthorization(authzURL, domain)
		if err != nil {
			fmt.Printf("Failed to process authorization: %v\n", err)
			return
		}
	}
	finalOrder, err := finalizeOrder(order.Finalize, orderURL, domain)
	if err != nil {
		fmt.Printf("Failed to finalize order: %v\n", err)
		return
	}
	cert, err := downloadCertificate(finalOrder.Certificate)
	if err != nil {
		fmt.Printf("Failed to download certificate: %v\n", err)
		return
	}
	saveCertAndKey(cert)
	fmt.Println("Certificate obtained successfully!")
}

func getDirectory() (*Directory, error) {
	resp, err := http.Get(directoryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dir Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, err
	}

	fmt.Println("Directory fetched successfully")
	return &dir, nil
}

func getNonce(nonceURL string) error {
	resp, err := http.Head(nonceURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	nonce = resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return fmt.Errorf("no nonce in response")
	}

	return nil
}

func createAccount(newAccountURL string) (string, error) {
	account := Account{
		Contact:              []string{"mailto:" + email},
		TermsOfServiceAgreed: true,
	}
	resp, err := sendRequest(newAccountURL, account, true)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no account location in response")
	}
	fmt.Printf("Account created: %s\n", location)
	return location, nil
}

func createOrder(newOrderURL, domain string) (*Order, string, error) {
	var identifierType string
	if net.ParseIP(domain) != nil {
		identifierType = "ip"
	} else {
		identifierType = "dns"
	}
	orderReq := struct {
		Profile     string       `json:"profile"`
		Identifiers []Identifier `json:"identifiers"`
	}{
		Profile: "shortlived",
		Identifiers: []Identifier{
			{Type: identifierType, Value: domain},
		},
	}
	resp, err := sendRequest(newOrderURL, orderReq, false)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var order Order
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, "", err
	}
	location := resp.Header.Get("Location")
	fmt.Printf("Order created: %s\n", location)
	return &order, location, nil
}

func processAuthorization(authzURL, domain string) error {
	resp, err := sendRequest(authzURL, nil, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var authz Authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return err
	}
	var httpChallenge *Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			httpChallenge = &ch
			break
		}
	}
	if httpChallenge == nil {
		return fmt.Errorf("no http-01 challenge found")
	}
	keyAuth := httpChallenge.Token + "." + thumbprint()
	startHTTPServer(httpChallenge.Token, keyAuth, domain)
	defer stopHTTPServer()
	_, err = sendRequest(httpChallenge.URL, map[string]string{}, false)
	if err != nil {
		return err
	}
	fmt.Println("Waiting for challenge validation...")
	time.Sleep(5 * time.Second)
	for i := 0; i < 30; i++ {
		resp, err = sendRequest(authzURL, nil, false)
		if err != nil {
			return err
		}

		var status Authorization
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()
		if status.Status == "valid" {
			fmt.Println("Authorization validated")
			return nil
		} else if status.Status == "invalid" {
			return fmt.Errorf("authorization failed")
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("authorization timeout")
}

func finalizeOrder(finalizeURL, orderURL string, domain string) (*Order, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "TinyACME User",
		},
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, certKey)
	if err != nil {
		return nil, err
	}
	csrReq := struct {
		CSR string `json:"csr"`
	}{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}
	_, err = sendRequest(finalizeURL, csrReq, false)
	if err != nil {
		return nil, err
	}
	fmt.Println("Waiting for certificate...")
	for i := 0; i < 30; i++ {
		time.Sleep(3 * time.Second)
		resp, err := sendRequest(orderURL, nil, false)
		if err != nil {
			return nil, err
		}
		var order Order
		if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		if order.Status == "valid" && order.Certificate != "" {
			fmt.Println("Certificate ready")
			return &order, nil
		}
	}
	return nil, fmt.Errorf("certificate timeout")
}

func downloadCertificate(certURL string) (string, error) {
	resp, err := sendRequest(certURL, nil, false)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	cert, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(cert), nil
}

func startHTTPServer(token, keyAuth, domain string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/"+token, func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Serving challenge response for %s\n", r.RemoteAddr)
		w.Write([]byte(keyAuth))
	})
	httpServer = &http.Server{
		Addr:    ":80",
		Handler: mux,
	}
	go func() {
		fmt.Printf("Starting HTTP server on %s:80\n", domain)
		if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()
	time.Sleep(2 * time.Second)
}

func stopHTTPServer() {
	if httpServer != nil {
		httpServer.Close()
		fmt.Println("HTTP server stopped")
	}
}

func saveCertAndKey(cert string) {
	certFile := fmt.Sprintf("cert.cer")
	if err := os.WriteFile(certFile, []byte(cert), 0777); err != nil {
		fmt.Printf("Failed to save certificate: %v\n", err)
		return
	}
	fmt.Printf("Certificate saved to %s\n", certFile)
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %v\n", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	keyFile := fmt.Sprintf("key.pem")
	if err := os.WriteFile(keyFile, keyPEM, 0777); err != nil {
		fmt.Printf("Failed to save private key: %v\n", err)
		return
	}
	fmt.Printf("Private key saved to %s\n", keyFile)
}

type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwsProtected struct {
	Alg   string      `json:"alg"`
	Nonce string      `json:"nonce"`
	URL   string      `json:"url"`
	Kid   string      `json:"kid,omitempty"`
	Jwk   interface{} `json:"jwk,omitempty"`
}

type jwkEC struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func createJWS(url string, payload []byte, useJWK bool) (*JWS, error) {
	protected := jwsProtected{
		Alg:   "ES256",
		Nonce: nonce,
		URL:   url,
	}
	if useJWK {
		protected.Jwk = getJWK()
	} else {
		protected.Kid = kid
	}
	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sigData := protectedB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(sigData))
	r, s, err := ecdsa.Sign(rand.Reader, accountKey, hash[:])
	if err != nil {
		return nil, err
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	return &JWS{
		Protected: protectedB64,
		Payload:   payloadB64,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

func getJWK() jwkEC {
	pub := accountKey.Public().(*ecdsa.PublicKey)
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)
	return jwkEC{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

func thumbprint() string {
	jwk := getJWK()
	data := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func sendRequest(url string, payload interface{}, useJWK bool) (*http.Response, error) {
	var payloadBytes []byte
	var err error
	if payload == nil {
		payloadBytes = []byte("")
	} else {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	jws, err := createJWS(url, payloadBytes, useJWK)
	if err != nil {
		return nil, err
	}
	jwsBytes, err := json.Marshal(jws)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(jwsBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
		nonce = newNonce
	}
	return resp, nil
}

type Directory struct {
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
}

type Account struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

type Order struct {
	Status         string       `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Authorization struct {
	Status     string      `json:"status"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}
