package captcha

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenValidityAndExpiry(t *testing.T) {
	manager := NewManager("secret", time.Minute)
	now := time.Unix(100, 0)
	manager.SetClock(func() time.Time { return now })
	w := httptest.NewRecorder()
	manager.SetToken(w, 1, "192.0.2.10")
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	if !manager.Valid(req, 1, "192.0.2.10") {
		t.Fatal("token should be valid")
	}
	manager.SetClock(func() time.Time { return now.Add(2 * time.Minute) })
	if manager.Valid(req, 1, "192.0.2.10") {
		t.Fatal("token should expire")
	}
}
