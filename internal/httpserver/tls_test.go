package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"aegis-waf/internal/config"
	"aegis-waf/internal/database"
)

func TestTLSConfigSelectsCertificateBySNI(t *testing.T) {
	certPEM, keyPEM := selfSignedCertPEM(t, "secure.local")
	cert := database.Certificate{Name: "secure-cert", CertPEM: certPEM, KeyPEM: keyPEM}
	if err := cert.SetDomains([]string{"secure.local"}); err != nil {
		t.Fatal(err)
	}
	server := New(config.ServerConfig{}, config.SecurityConfig{}, &processorStub{})
	server.runtime = runtimeForTest(t, database.Site{ID: 1, Name: "secure", Upstream: "http://127.0.0.1:8081", Status: database.SiteStatusEnabled, TLSMode: "custom", CertificateID: 7, WAFEnabled: true})
	server.certificates.Store(certificateSnapshot{ByID: map[uint]database.Certificate{7: cert}, ByDomain: map[string]database.Certificate{"secure.local": cert}})

	tlsConfig := server.TLSConfig()
	if tlsConfig == nil || tlsConfig.GetCertificate == nil {
		t.Fatal("TLSConfig/GetCertificate not configured")
	}
	got, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "secure.local"})
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatalf("certificate not returned: %#v", got)
	}
}

func TestTLSConfigReturnsACMECertificateForAutoSite(t *testing.T) {
	certPEM, keyPEM := selfSignedCertPEM(t, "auto.local")
	server := New(config.ServerConfig{TLS: config.TLSConfig{ACME: config.ACMEConfig{Enabled: true, AcceptTOS: true}}}, config.SecurityConfig{}, &processorStub{})
	autoSite := database.Site{ID: 1, Name: "auto", Upstream: "http://127.0.0.1:8081", Status: database.SiteStatusEnabled, TLSMode: "auto", WAFEnabled: true}
	if err := autoSite.SetDomains([]string{"auto.local"}); err != nil {
		t.Fatal(err)
	}
	server.runtime = runtimeForTest(t, autoSite)
	server.acmeManager = acmeCertificateProviderFunc(func(ctx context.Context, domain string) (*tls.Certificate, error) {
		if domain != "auto.local" {
			t.Fatalf("domain = %q, want auto.local", domain)
		}
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, err
		}
		return &cert, nil
	})

	got, err := server.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "auto.local"})
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if got == nil || len(got.Certificate) == 0 {
		t.Fatalf("ACME certificate not returned: %#v", got)
	}
}

func TestStartEnablesHTTPSListenerWhenConfigured(t *testing.T) {
	server := New(config.ServerConfig{TLS: config.TLSConfig{Enabled: true, Port: 9443}}, config.SecurityConfig{}, &processorStub{})
	if !server.HTTPSAddrEnabled() {
		t.Fatal("HTTPS listener should be enabled")
	}
	if server.HTTPSAddr() != "0.0.0.0:9443" {
		t.Fatalf("https addr = %q, want 0.0.0.0:9443", server.HTTPSAddr())
	}
}

type acmeCertificateProviderFunc func(context.Context, string) (*tls.Certificate, error)

func (f acmeCertificateProviderFunc) GetCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	return f(ctx, domain)
}

func selfSignedCertPEM(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}
