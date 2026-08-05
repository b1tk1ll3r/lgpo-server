package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gpo-distributor/internal/bundle"
	"gpo-distributor/internal/model"
)

func TestResolveLatest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "x.zip")
	if err := os.WriteFile(zipPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, hash := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} {
		_, _, err := s.ImportPolicy("baseline", "", zipPath, bundle.Inspection{ArtifactHash: hash, SemanticHash: hash, Size: 1, FileCount: 1, PolicyFiles: 1}, base.Add(time.Duration(i)*time.Second), false)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SetProfile("servers", []model.ProfilePolicy{{Policy: "baseline", Version: "latest"}}, base); err != nil {
		t.Fatal(err)
	}
	m, err := s.ResolveManifest("servers")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Policies[0].SemanticHash; got[0] != 'b' {
		t.Fatalf("expected latest, got %s", got)
	}
}

func TestDeletePolicyVersionAndReferences(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(zipPath, []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 5, 8, 0, 0, 0, time.UTC)
	var versions []model.PolicyVersion
	for i, hash := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		version, _, err := s.ImportPolicy("baseline", "", zipPath, bundle.Inspection{
			ArtifactHash: hash,
			SemanticHash: hash,
			Size:         6,
			FileCount:    1,
			PolicyFiles:  1,
		}, base.Add(time.Duration(i)*time.Second), false)
		if err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	if _, err := s.SetProfile("servers", []model.ProfilePolicy{{Policy: "baseline", Version: versions[0].Version}}, base); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicyVersion("baseline", versions[0].Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected pinned version conflict, got %v", err)
	}
	if err := s.DeletePolicy("baseline"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected referenced policy conflict, got %v", err)
	}
	if err := s.DeleteProfile("servers"); err != nil {
		t.Fatal(err)
	}
	_, artifact, err := s.Artifact("baseline", versions[0].Version)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicyVersion("baseline", versions[0].Version); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact still exists or unexpected stat error: %v", err)
	}
	if err := s.DeletePolicyVersion("baseline", versions[1].Version); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected last-version conflict, got %v", err)
	}
	if err := s.DeletePolicy("baseline"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPolicy("baseline"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected deleted policy to be missing, got %v", err)
	}
}
