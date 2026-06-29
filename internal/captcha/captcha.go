package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const CookieName = "aegis_challenge_token"

type Manager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

func NewManager(secret string, ttl time.Duration) *Manager {
	if secret == "" {
		secret = "aegis-waf-dev-secret"
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Manager{secret: []byte(secret), ttl: ttl, now: time.Now}
}

func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

func (m *Manager) Valid(r *http.Request, siteID uint, ip string) bool {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || m.now().Unix() > expiry {
		return false
	}
	want := m.sign(parts[0], expiry, siteID, ip)
	return hmac.Equal([]byte(parts[2]), []byte(want))
}

func (m *Manager) SetToken(w http.ResponseWriter, siteID uint, ip string) {
	expiry := m.now().Add(m.ttl).Unix()
	nonce := fmt.Sprintf("%d", m.now().UnixNano())
	value := fmt.Sprintf("%s:%d:%s", nonce, expiry, m.sign(nonce, expiry, siteID, ip))
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: value, Path: "/", Expires: time.Unix(expiry, 0), HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (m *Manager) ChallengeHTML() string {
	return `<!doctype html><html><head><meta charset="utf-8"><title>Aegis Challenge</title></head><body><h1>Security Challenge</h1><form method="post" action="/challenge/verify"><button type="submit">Verify</button></form></body></html>`
}

func (m *Manager) sign(nonce string, expiry int64, siteID uint, ip string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(fmt.Sprintf("%s:%d:%d:%s", nonce, expiry, siteID, ip)))
	return hex.EncodeToString(mac.Sum(nil))
}
