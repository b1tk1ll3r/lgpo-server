package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gpo-distributor/internal/bundle"
	"gpo-distributor/internal/model"
)

type Config struct {
	ServerURL          string `json:"server_url"`
	Profile            string `json:"profile"`
	ClientToken        string `json:"client_token"`
	SigningKey         string `json:"signing_key"`
	LGPOPath           string `json:"lgpo_path"`
	StateDir           string `json:"state_dir"`
	PollInterval       string `json:"poll_interval"`
	ClientID           string `json:"client_id,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	RequestTimeout     string `json:"request_timeout,omitempty"`
}

type State struct {
	Generation string                 `json:"generation"`
	AppliedAt  time.Time              `json:"applied_at"`
	Policies   []model.ResolvedPolicy `json:"policies"`
}

type Runner struct {
	cfg       Config
	client    *http.Client
	logger    *log.Logger
	version   string
	interval  time.Duration
	clientID  string
	hostname  string
	stateFile string
}

func LoadConfig(filename string) (Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func New(cfg Config, version string, logger *log.Logger) (*Runner, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	interval, err := time.ParseDuration(cfg.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("poll_interval: %w", err)
	}
	if interval < time.Minute {
		return nil, errors.New("poll_interval must be at least 1m")
	}
	timeout := 10 * time.Minute
	if cfg.RequestTimeout != "" {
		timeout, err = time.ParseDuration(cfg.RequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("request_timeout: %w", err)
		}
	}
	if logger == nil {
		logger = log.Default()
	}
	host, _ := os.Hostname()
	clientID := cfg.ClientID
	if clientID == "" {
		clientID = host
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} // #nosec G402: explicit opt-in for test environments.
	return &Runner{
		cfg: cfg, version: version, logger: logger, interval: interval,
		client:   &http.Client{Timeout: timeout, Transport: transport},
		clientID: clientID, hostname: host,
		stateFile: filepath.Join(cfg.StateDir, "state.json"),
	}, nil
}

func validateConfig(cfg Config) error {
	if cfg.ServerURL == "" || cfg.Profile == "" || cfg.ClientToken == "" || cfg.SigningKey == "" || cfg.LGPOPath == "" || cfg.StateDir == "" {
		return errors.New("server_url, profile, client_token, signing_key, lgpo_path and state_dir are required")
	}
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("server_url must be an absolute URL")
	}
	if u.Scheme != "https" && !cfg.InsecureSkipVerify {
		return errors.New("server_url must use https (or set insecure_skip_verify only for tests)")
	}
	if cfg.PollInterval == "" {
		return errors.New("poll_interval is required")
	}
	return nil
}

func (r *Runner) Run(ctx context.Context, once bool) error {
	if err := os.MkdirAll(r.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if once {
		return r.Sync(ctx)
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		if err := r.Sync(ctx); err != nil {
			r.logger.Printf("sync failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Runner) Sync(ctx context.Context) (retErr error) {
	state, err := r.loadState()
	if err != nil {
		return err
	}
	manifest, changed, err := r.fetchManifest(ctx, state.Generation)
	if err != nil {
		r.report(ctx, model.ClientReport{ClientID: r.clientID, Hostname: r.hostname, Profile: r.cfg.Profile, Generation: state.Generation, Success: false, Message: err.Error(), AgentVersion: r.version, OperatingSystem: runtime.GOOS})
		return err
	}
	if !changed {
		r.logger.Printf("profile=%s generation=%s status=up-to-date", r.cfg.Profile, state.Generation)
		return nil
	}

	unlock, err := acquireLock(filepath.Join(r.cfg.StateDir, "agent.lock"), 2*time.Hour)
	if err != nil {
		return err
	}
	defer unlock()

	staging, err := os.MkdirTemp(r.cfg.StateDir, "staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	policyDirs := make([]string, 0, len(manifest.Policies))
	for i, p := range manifest.Policies {
		zipPath, err := r.obtainArtifact(ctx, p)
		if err != nil {
			return r.failAndReport(ctx, manifest.Generation, fmt.Errorf("download %s: %w", p.Name, err))
		}
		dir := filepath.Join(staging, fmt.Sprintf("%03d-%s", i, p.Name))
		if err := bundle.ExtractZip(zipPath, dir, bundle.ExtractLimits{}); err != nil {
			return r.failAndReport(ctx, manifest.Generation, fmt.Errorf("extract %s: %w", p.Name, err))
		}
		importRoot, err := bundle.FindImportRoot(dir)
		if err != nil {
			return r.failAndReport(ctx, manifest.Generation, fmt.Errorf("locate GPO root for %s: %w", p.Name, err))
		}
		policyDirs = append(policyDirs, importRoot)
	}

	rollbackRoot := filepath.Join(r.cfg.StateDir, "rollback", time.Now().UTC().Format("20060102-150405"))
	if err := os.MkdirAll(rollbackRoot, 0o700); err != nil {
		return r.failAndReport(ctx, manifest.Generation, err)
	}
	if err := backupLocalPolicy(ctx, r.cfg.LGPOPath, rollbackRoot); err != nil {
		return r.failAndReport(ctx, manifest.Generation, fmt.Errorf("pre-apply backup failed: %w", err))
	}

	if err := applyPolicyDirectories(ctx, r.cfg.LGPOPath, policyDirs); err != nil {
		rollbackErr := restoreLocalPolicy(ctx, r.cfg.LGPOPath, rollbackRoot)
		if rollbackErr != nil {
			err = fmt.Errorf("apply failed: %v; rollback also failed: %w", err, rollbackErr)
		} else {
			err = fmt.Errorf("apply failed and rollback succeeded: %w", err)
		}
		return r.failAndReport(ctx, manifest.Generation, err)
	}

	newState := State{Generation: manifest.Generation, AppliedAt: time.Now().UTC(), Policies: manifest.Policies}
	if err := r.saveState(newState); err != nil {
		return r.failAndReport(ctx, manifest.Generation, fmt.Errorf("save state: %w", err))
	}
	r.pruneRollbacks(filepath.Join(r.cfg.StateDir, "rollback"), 5)
	r.report(ctx, model.ClientReport{ClientID: r.clientID, Hostname: r.hostname, Profile: r.cfg.Profile, Generation: manifest.Generation, Success: true, Message: "policy profile applied", AgentVersion: r.version, AppliedAt: newState.AppliedAt, OperatingSystem: runtime.GOOS})
	r.logger.Printf("profile=%s generation=%s policies=%d status=applied", r.cfg.Profile, manifest.Generation, len(manifest.Policies))
	return nil
}

func (r *Runner) fetchManifest(ctx context.Context, current string) (model.Manifest, bool, error) {
	base, _ := url.Parse(strings.TrimRight(r.cfg.ServerURL, "/") + "/")
	rel, _ := url.Parse("api/v1/profiles/" + url.PathEscape(r.cfg.Profile) + "/manifest")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.ResolveReference(rel).String(), nil)
	if err != nil {
		return model.Manifest{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.ClientToken)
	if current != "" {
		req.Header.Set("If-None-Match", `"`+current+`"`)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return model.Manifest{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return model.Manifest{}, false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return model.Manifest{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return model.Manifest{}, false, fmt.Errorf("manifest HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := verifySignature(body, resp.Header.Get("X-GPO-Signature"), r.cfg.SigningKey); err != nil {
		return model.Manifest{}, false, err
	}
	var manifest model.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return model.Manifest{}, false, err
	}
	if manifest.Profile != r.cfg.Profile || manifest.Generation == "" {
		return model.Manifest{}, false, errors.New("invalid manifest identity")
	}
	if manifest.Generation == current {
		return manifest, false, nil
	}
	return manifest, true, nil
}

func verifySignature(body []byte, header, key string) error {
	const prefix = "hmac-sha256="
	if !strings.HasPrefix(header, prefix) {
		return errors.New("manifest signature missing")
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return errors.New("invalid manifest signature encoding")
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

func (r *Runner) obtainArtifact(ctx context.Context, p model.ResolvedPolicy) (string, error) {
	if len(p.SHA256) != 64 || p.Size <= 0 {
		return "", errors.New("invalid artifact metadata")
	}
	cacheDir := filepath.Join(r.cfg.StateDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", err
	}
	final := filepath.Join(cacheDir, p.SHA256+".zip")
	if ok, _ := verifyFile(final, p.SHA256, p.Size); ok {
		return final, nil
	}

	base, _ := url.Parse(strings.TrimRight(r.cfg.ServerURL, "/") + "/")
	rel, err := url.Parse(strings.TrimLeft(p.DownloadURL, "/"))
	if err != nil {
		return "", err
	}
	u := base.ResolveReference(rel)
	if u.Host != base.Host || u.Scheme != base.Scheme {
		return "", errors.New("artifact URL points to a different origin")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.ClientToken)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	tmp, err := os.CreateTemp(cacheDir, ".download-*.zip")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, p.Size+1))
	closeErr := tmp.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != p.Size {
		return "", fmt.Errorf("artifact size mismatch: expected %d, got %d", p.Size, n)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.SHA256 {
		return "", fmt.Errorf("artifact hash mismatch: expected %s, got %s", p.SHA256, got)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", err
	}
	return final, nil
}

func verifyFile(filename, expectedHash string, expectedSize int64) (bool, error) {
	f, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, err
	}
	if st.Size() != expectedSize {
		return false, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == expectedHash, nil
}

func (r *Runner) loadState() (State, error) {
	b, err := os.ReadFile(r.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, err
	}
	return st, nil
}

func (r *Runner) saveState(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.stateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.stateFile)
}

func acquireLock(filename string, staleAfter time.Duration) (func(), error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
		_ = f.Close()
		return func() { _ = os.Remove(filename) }, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	st, statErr := os.Stat(filename)
	if statErr == nil && time.Since(st.ModTime()) > staleAfter {
		if removeErr := os.Remove(filename); removeErr == nil {
			return acquireLock(filename, staleAfter)
		}
	}
	return nil, errors.New("another agent instance is running")
}

func (r *Runner) failAndReport(ctx context.Context, generation string, err error) error {
	r.report(ctx, model.ClientReport{ClientID: r.clientID, Hostname: r.hostname, Profile: r.cfg.Profile, Generation: generation, Success: false, Message: err.Error(), AgentVersion: r.version, OperatingSystem: runtime.GOOS})
	return err
}

func (r *Runner) report(ctx context.Context, report model.ClientReport) {
	body, err := json.Marshal(report)
	if err != nil {
		return
	}
	base := strings.TrimRight(r.cfg.ServerURL, "/") + "/api/v1/client/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+r.cfg.ClientToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		r.logger.Printf("report failed: %v", err)
		return
	}
	_ = resp.Body.Close()
}

func (r *Runner) pruneRollbacks(root string, keep int) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	if len(dirs) <= keep {
		return
	}
	// Names are UTC timestamps, so lexical order is chronological.
	for i := 0; i < len(dirs)-keep; i++ {
		_ = os.RemoveAll(filepath.Join(root, dirs[i].Name()))
	}
}
