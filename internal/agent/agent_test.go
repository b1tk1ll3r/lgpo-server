package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAcceptsUTF8BOM(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "agent.json")
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{
		"server_url":"http://127.0.0.1:8080",
		"profile":"servers",
		"client_token":"token",
		"signing_key":"key",
		"lgpo_path":"C:\\LGPO.exe",
		"state_dir":"C:\\ProgramData\\GPO-Distributor",
		"poll_interval":"15m",
		"insecure_skip_verify":true
	}`)...)
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "servers" {
		t.Fatalf("unexpected profile: %s", cfg.Profile)
	}
}
