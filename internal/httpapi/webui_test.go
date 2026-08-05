package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"gpo-distributor/internal/store"
)

func TestWebSessionAndCSRF(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(st, Config{
		AdminToken:    "admin-secret-with-sufficient-entropy",
		ClientToken:   "client-secret-with-sufficient-entropy",
		SigningKey:    "manifest-secret-with-sufficient-entropy",
		ServerVersion: "test",
		Logger:        log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := api.Handler()

	loginBody := bytes.NewBufferString(`{"token":"admin-secret-with-sufficient-entropy"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/ui/api/session", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminSessionCookie {
		t.Fatalf("expected admin session cookie, got %#v", cookies)
	}
	var loginResponse struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResponse); err != nil {
		t.Fatal(err)
	}
	if loginResponse.CSRF == "" {
		t.Fatal("missing CSRF token")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/policies", nil)
	listReq.AddCookie(cookies[0])
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRec.Code, listRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/clients/missing", nil)
	deleteReq.AddCookie(cookies[0])
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusForbidden {
		t.Fatalf("delete without CSRF status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}

	deleteReq = httptest.NewRequest(http.MethodDelete, "/api/v1/admin/clients/missing", nil)
	deleteReq.AddCookie(cookies[0])
	deleteReq.Header.Set("X-CSRF-Token", loginResponse.CSRF)
	deleteRec = httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNotFound {
		t.Fatalf("delete with CSRF status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestEmbeddedUIAndBearerCompatibility(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(st, Config{
		AdminToken:  "admin-token",
		ClientToken: "client-token",
		SigningKey:  "signing-key",
		Logger:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := api.Handler()

	uiReq := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	uiRec := httptest.NewRecorder()
	handler.ServeHTTP(uiRec, uiReq)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("ui status=%d", uiRec.Code)
	}
	if got := uiRec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("missing CSP header")
	}
	if !bytes.Contains(uiRec.Body.Bytes(), []byte("GPO Distributor")) {
		t.Fatal("embedded UI body is unexpected")
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/profiles", nil)
	apiReq.Header.Set("Authorization", "Bearer admin-token")
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusOK {
		t.Fatalf("bearer status=%d body=%s", apiRec.Code, apiRec.Body.String())
	}
}
