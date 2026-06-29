package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aegis-waf/internal/config"
	"aegis-waf/internal/pipeline"
)

func TestCertificatesAPIStoresAndListsCertificates(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	body := `{"name":"example-cert","domains":["example.com","www.example.com"],"certPem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----","keyPem":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"}`
	create := httptest.NewRecorder()
	server.Handler().ServeHTTP(create, httptest.NewRequest(http.MethodPost, "/api/certificates", strings.NewReader(body)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created certificateResponse
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Name != "example-cert" || len(created.Domains) != 2 || created.HasPrivateKey != true {
		t.Fatalf("unexpected created certificate: %#v", created)
	}
	if strings.Contains(create.Body.String(), "PRIVATE KEY") {
		t.Fatalf("private key leaked in response: %s", create.Body.String())
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/certificates", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var listed certificateListResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 1 || listed.Certificates[0].Name != "example-cert" {
		t.Fatalf("unexpected list: %#v", listed)
	}
}

func TestSiteCanBindCertificate(t *testing.T) {
	db := testDB(t)
	server := New(config.ServerConfig{}, config.SecurityConfig{MaxBodySize: 1024}, &processorStub{result: pipeline.Result{Decision: pipeline.DecisionAllow}}, WithDatabase(db))

	certBody := `{"name":"bound-cert","domains":["bound.local"],"certPem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----","keyPem":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"}`
	certCreate := httptest.NewRecorder()
	server.Handler().ServeHTTP(certCreate, httptest.NewRequest(http.MethodPost, "/api/certificates", strings.NewReader(certBody)))
	if certCreate.Code != http.StatusCreated {
		t.Fatalf("cert create status=%d body=%s", certCreate.Code, certCreate.Body.String())
	}

	siteBody := `{"name":"tls-site","domains":["bound.local"],"upstream":"http://127.0.0.1:8081","tlsMode":"custom","certificateId":"1","wafEnabled":true}`
	siteCreate := httptest.NewRecorder()
	server.Handler().ServeHTTP(siteCreate, httptest.NewRequest(http.MethodPost, "/api/sites", strings.NewReader(siteBody)))
	if siteCreate.Code != http.StatusCreated {
		t.Fatalf("site create status=%d body=%s", siteCreate.Code, siteCreate.Body.String())
	}
	var site protectedSite
	if err := json.Unmarshal(siteCreate.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	if site.TLSMode != "custom" || site.CertificateID != "1" || site.CertificateName != "bound-cert" {
		t.Fatalf("site certificate binding missing: %#v", site)
	}

	runtimeSite, ok := server.runtime.MatchSite("bound.local")
	if !ok {
		t.Fatal("runtime site not found")
	}
	if runtimeSite.CertificateID != 1 || runtimeSite.CertificateName != "bound-cert" {
		t.Fatalf("runtime certificate binding missing: %#v", runtimeSite)
	}
}
