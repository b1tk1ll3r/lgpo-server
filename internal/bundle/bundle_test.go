package bundle

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func createZip(t *testing.T, files map[string]string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "bundle.zip")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for path, content := range files {
		w, err := zw.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSemanticHashIgnoresBackupMetadata(t *testing.T) {
	base := map[string]string{
		"manifest.xml":     "time=one",
		"{A}/backup.xml":   "version=1",
		"{A}/bkupInfo.xml": "time=one",
		"{A}/DomainSysvol/GPO/Machine/registry.pol": "policy",
	}
	a := createZip(t, base)
	base["manifest.xml"] = "time=two"
	base["{A}/bkupInfo.xml"] = "time=two"
	base["{A}/backup.xml"] = "version=2"
	b := createZip(t, base)
	ia, err := InspectZip(a)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := InspectZip(b)
	if err != nil {
		t.Fatal(err)
	}
	if ia.SemanticHash != ib.SemanticHash {
		t.Fatalf("semantic hashes differ: %s != %s", ia.SemanticHash, ib.SemanticHash)
	}
	if ia.ArtifactHash == ib.ArtifactHash {
		t.Fatal("artifact hashes should differ")
	}
}

func TestSemanticHashChangesWithPolicy(t *testing.T) {
	a := createZip(t, map[string]string{
		"{A}/backup.xml": "x",
		"{A}/DomainSysvol/GPO/Machine/registry.pol": "one",
	})
	b := createZip(t, map[string]string{
		"{A}/backup.xml": "x",
		"{A}/DomainSysvol/GPO/Machine/registry.pol": "two",
	})
	ia, _ := InspectZip(a)
	ib, _ := InspectZip(b)
	if ia.SemanticHash == ib.SemanticHash {
		t.Fatal("semantic hashes should differ")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	z := createZip(t, map[string]string{"../evil": "x"})
	if err := ExtractZip(z, t.TempDir(), ExtractLimits{}); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestFindImportRootWrappedArchive(t *testing.T) {
	root := t.TempDir()
	backupRoot := filepath.Join(root, "wrapper", "backup")
	if err := os.MkdirAll(filepath.Join(backupRoot, "{A}"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupRoot, "manifest.xml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupRoot, "{A}", "backup.xml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := FindImportRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != backupRoot {
		t.Fatalf("got %s, want %s", got, backupRoot)
	}
}
