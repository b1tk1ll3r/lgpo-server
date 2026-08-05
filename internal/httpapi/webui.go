package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	adminSessionCookie = "gpo_admin_session"
	adminSessionTTL    = 8 * time.Hour
)

//go:embed ui/*
var embeddedUI embed.FS

type adminSession struct {
	ExpiresAt int64  `json:"exp"`
	CSRF      string `json:"csrf"`
	Nonce     string `json:"nonce"`
}

func (s *Server) registerWebUI() {
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
	})
	s.mux.HandleFunc("POST /ui/api/session", s.createWebSession)
	s.mux.HandleFunc("GET /ui/api/session", s.getWebSession)
	s.mux.HandleFunc("DELETE /ui/api/session", s.deleteWebSession)
	s.mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
	})
	s.mux.HandleFunc("GET /ui/{$}", s.serveUIIndex)
	s.mux.HandleFunc("GET /ui/{asset...}", s.serveUIAsset)
}

func (s *Server) serveUIIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbeddedFile(w, r, "ui/index.html")
}

func (s *Server) serveUIAsset(w http.ResponseWriter, r *http.Request) {
	asset := path.Clean(r.PathValue("asset"))
	if asset == "." || strings.HasPrefix(asset, "../") || strings.Contains(asset, "\\") {
		http.NotFound(w, r)
		return
	}
	if asset != "app.js" && asset != "styles.css" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbeddedFile(w, r, "ui/"+asset)
}

func (s *Server) serveEmbeddedFile(w http.ResponseWriter, r *http.Request, name string) {
	data, err := fs.ReadFile(embeddedUI, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", contentType)
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) createWebSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, &request, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !constantTimeEqual(request.Token, s.cfg.AdminToken) {
		writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	nonce, err := randomToken(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	session := adminSession{ExpiresAt: time.Now().Add(adminSessionTTL).Unix(), CSRF: csrf, Nonce: nonce}
	value, err := s.signAdminSession(session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(adminSessionTTL.Seconds()),
		Expires:  time.Unix(session.ExpiresAt, 0),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf_token": csrf,
		"expires_at": time.Unix(session.ExpiresAt, 0).UTC(),
		"version":    s.cfg.ServerVersion,
	})
}

func (s *Server) getWebSession(w http.ResponseWriter, r *http.Request) {
	session, err := s.readAdminSession(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf_token": session.CSRF,
		"expires_at": time.Unix(session.ExpiresAt, 0).UTC(),
		"version":    s.cfg.ServerVersion,
	})
}

func (s *Server) deleteWebSession(w http.ResponseWriter, r *http.Request) {
	if session, err := s.readAdminSession(r); err == nil {
		provided := r.Header.Get("X-CSRF-Token")
		if !constantTimeEqual(provided, session.CSRF) {
			writeError(w, http.StatusForbidden, errors.New("invalid CSRF token"))
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Cache-Control", "no-store")
		if auth != "" {
			if !strings.HasPrefix(auth, "Bearer ") || !constantTimeEqual(strings.TrimPrefix(auth, "Bearer "), s.cfg.AdminToken) {
				writeError(w, http.StatusForbidden, errors.New("invalid bearer token"))
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		session, err := s.readAdminSession(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		if methodNeedsCSRF(r.Method) && !constantTimeEqual(r.Header.Get("X-CSRF-Token"), session.CSRF) {
			writeError(w, http.StatusForbidden, errors.New("invalid CSRF token"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) signAdminSession(session adminSession) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(s.cfg.AdminToken))
	_, _ = mac.Write([]byte("gpo-web-session-v1\x00"))
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) readAdminSession(r *http.Request) (adminSession, error) {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil {
		return adminSession{}, err
	}
	encoded, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok || encoded == "" || signature == "" {
		return adminSession{}, errors.New("malformed session")
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return adminSession{}, errors.New("malformed session signature")
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.AdminToken))
	_, _ = mac.Write([]byte("gpo-web-session-v1\x00"))
	_, _ = mac.Write([]byte(encoded))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return adminSession{}, errors.New("invalid session signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return adminSession{}, errors.New("malformed session payload")
	}
	var session adminSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return adminSession{}, errors.New("malformed session payload")
	}
	if session.ExpiresAt <= time.Now().Unix() || session.CSRF == "" || session.Nonce == "" {
		return adminSession{}, errors.New("expired session")
	}
	return session, nil
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func constantTimeEqual(provided, expected string) bool {
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func methodNeedsCSRF(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/ui") || r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}
