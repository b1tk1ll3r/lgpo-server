package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gpo-distributor/internal/bundle"
	"gpo-distributor/internal/model"
	"gpo-distributor/internal/store"
)

type Config struct {
	AdminToken    string
	ClientToken   string
	SigningKey    string
	ServerVersion string
	MaxUpload     int64
	Logger        *log.Logger
}

type Server struct {
	store *store.Store
	cfg   Config
	mux   *http.ServeMux
}

func New(s *store.Store, cfg Config) (*Server, error) {
	if cfg.AdminToken == "" || cfg.ClientToken == "" || cfg.SigningKey == "" {
		return nil, errors.New("admin token, client token and signing key are required")
	}
	if cfg.MaxUpload <= 0 {
		cfg.MaxUpload = 512 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	api := &Server{store: s, cfg: cfg, mux: http.NewServeMux()}
	api.routes()
	return api, nil
}

func (s *Server) Handler() http.Handler {
	return s.logRequests(s.securityHeaders(s.mux))
}

func (s *Server) routes() {
	s.registerWebUI()

	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.cfg.ServerVersion})
	})

	s.mux.Handle("POST /api/v1/admin/policies/{name}/versions", s.requireAdmin(http.HandlerFunc(s.uploadPolicy)))
	s.mux.Handle("GET /api/v1/admin/policies", s.requireAdmin(http.HandlerFunc(s.listPolicies)))
	s.mux.Handle("GET /api/v1/admin/policies/{name}", s.requireAdmin(http.HandlerFunc(s.getPolicy)))
	s.mux.Handle("DELETE /api/v1/admin/policies/{name}", s.requireAdmin(http.HandlerFunc(s.deletePolicy)))
	s.mux.Handle("DELETE /api/v1/admin/policies/{name}/versions/{version}", s.requireAdmin(http.HandlerFunc(s.deletePolicyVersion)))
	s.mux.Handle("GET /api/v1/admin/policies/{policy}/versions/{version}/artifact", s.requireAdmin(http.HandlerFunc(s.getArtifact)))

	s.mux.Handle("PUT /api/v1/admin/profiles/{name}", s.requireAdmin(http.HandlerFunc(s.setProfile)))
	s.mux.Handle("DELETE /api/v1/admin/profiles/{name}", s.requireAdmin(http.HandlerFunc(s.deleteProfile)))
	s.mux.Handle("GET /api/v1/admin/profiles", s.requireAdmin(http.HandlerFunc(s.listProfiles)))

	s.mux.Handle("GET /api/v1/admin/clients", s.requireAdmin(http.HandlerFunc(s.listClients)))
	s.mux.Handle("DELETE /api/v1/admin/clients/{id}", s.requireAdmin(http.HandlerFunc(s.deleteClient)))

	s.mux.Handle("GET /api/v1/profiles/{name}/manifest", s.requireToken(s.cfg.ClientToken, http.HandlerFunc(s.getManifest)))
	s.mux.Handle("GET /api/v1/artifacts/{policy}/{version}", s.requireToken(s.cfg.ClientToken, http.HandlerFunc(s.getArtifact)))
	s.mux.Handle("POST /api/v1/client/report", s.requireToken(s.cfg.ClientToken, http.HandlerFunc(s.clientReport)))
}

func (s *Server) uploadPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := store.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("multipart/form-data required: %w", err))
		return
	}

	tmp, err := os.CreateTemp("", "gpo-upload-*.zip")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	note := ""
	force := false
	found := false
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		switch part.FormName() {
		case "bundle":
			if found {
				part.Close()
				writeError(w, http.StatusBadRequest, errors.New("only one bundle is allowed"))
				return
			}
			found = true
			if _, err := io.Copy(tmp, io.LimitReader(part, s.cfg.MaxUpload+1)); err != nil {
				part.Close()
				writeError(w, http.StatusBadRequest, err)
				return
			}
		case "note":
			b, err := io.ReadAll(io.LimitReader(part, 4097))
			if err != nil {
				part.Close()
				writeError(w, http.StatusBadRequest, err)
				return
			}
			if len(b) > 4096 {
				part.Close()
				writeError(w, http.StatusBadRequest, errors.New("note too long"))
				return
			}
			note = string(b)
		case "force":
			b, err := io.ReadAll(io.LimitReader(part, 16))
			if err != nil {
				part.Close()
				writeError(w, http.StatusBadRequest, err)
				return
			}
			force = strings.EqualFold(strings.TrimSpace(string(b)), "true")
		}
		part.Close()
	}
	if !found {
		writeError(w, http.StatusBadRequest, errors.New("multipart field 'bundle' is required"))
		return
	}
	if err := tmp.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	inspection, err := bundle.InspectZip(tmpName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	version, created, err := s.store.ImportPolicy(name, note, tmpName, inspection, time.Now(), force)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"created": created, "version": version})
}

func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListPolicies())
}
func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetPolicy(r.PathValue("name"))
	if err != nil {
		handleStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := store.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.DeletePolicy(name); err != nil {
		handleStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deletePolicyVersion(w http.ResponseWriter, r *http.Request) {
	name, version := r.PathValue("name"), r.PathValue("version")
	if err := store.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := store.ValidateName(version); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.DeletePolicyVersion(name, version); err != nil {
		handleStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policies []model.ProfilePolicy `json:"policies"`
	}
	if err := decodeJSON(w, r, &body, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.store.SetProfile(r.PathValue("name"), body.Policies, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusBadRequest, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, p)
}
func (s *Server) listProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListProfiles())
}
func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := store.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.DeleteProfile(name); err != nil {
		handleStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) listClients(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListClientReports())
}
func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteClientReport(r.PathValue("id")); err != nil {
		handleStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := s.store.ResolveManifest(r.PathValue("name"))
	if err != nil {
		handleStoreError(w, err)
		return
	}
	etag := `"` + manifest.Generation + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.SigningKey))
	_, _ = mac.Write(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-GPO-Signature", "hmac-sha256="+hex.EncodeToString(mac.Sum(nil)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	policy, version := r.PathValue("policy"), r.PathValue("version")
	if err := store.ValidateName(policy); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := store.ValidateName(version); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	meta, filename, err := s.store.Artifact(policy, version)
	if err != nil {
		handleStoreError(w, err)
		return
	}
	f, err := os.Open(filename)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filepath.Base(filename)))
	w.Header().Set("ETag", `"`+meta.ArtifactHash+`"`)
	w.Header().Set("X-Content-SHA256", meta.ArtifactHash)
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	http.ServeContent(w, r, filepath.Base(filename), st.ModTime(), f)
}

func (s *Server) clientReport(w http.ResponseWriter, r *http.Request) {
	var report model.ClientReport
	if err := decodeJSON(w, r, &report, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	report.ReportedAt = time.Now().UTC()
	if err := s.store.PutClientReport(report); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireToken(expected string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		provided := strings.TrimPrefix(auth, "Bearer ")
		if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			writeError(w, http.StatusForbidden, errors.New("invalid bearer token"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.cfg.Logger.Printf("method=%s path=%s remote=%s duration=%s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func handleStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}
