package bundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	DefaultMaxFiles      = 20000
	DefaultMaxExpanded   = int64(2 << 30) // 2 GiB
	DefaultMaxSingleFile = int64(512 << 20)
)

type Inspection struct {
	ArtifactHash string
	SemanticHash string
	Size         int64
	FileCount    int
	PolicyFiles  int
}

type fileDigest struct {
	name string
	size uint64
	hash [sha256.Size]byte
}

func InspectZip(filename string) (Inspection, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Inspection{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return Inspection{}, err
	}
	artifact := sha256.New()
	if _, err := io.Copy(artifact, f); err != nil {
		return Inspection{}, err
	}

	zr, err := zip.OpenReader(filename)
	if err != nil {
		return Inspection{}, fmt.Errorf("invalid ZIP: %w", err)
	}
	defer zr.Close()

	if len(zr.File) == 0 {
		return Inspection{}, errors.New("ZIP is empty")
	}
	if len(zr.File) > DefaultMaxFiles {
		return Inspection{}, fmt.Errorf("ZIP has too many entries: %d", len(zr.File))
	}

	var total uint64
	var payload []fileDigest
	backupXML := 0
	fileCount := 0

	for _, zf := range zr.File {
		name, err := cleanArchivePath(zf.Name)
		if err != nil {
			return Inspection{}, err
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if !zf.Mode().IsRegular() {
			return Inspection{}, fmt.Errorf("unsupported ZIP entry type: %q", zf.Name)
		}
		if zf.UncompressedSize64 > uint64(DefaultMaxSingleFile) {
			return Inspection{}, fmt.Errorf("ZIP entry too large: %q", zf.Name)
		}
		total += zf.UncompressedSize64
		if total > uint64(DefaultMaxExpanded) {
			return Inspection{}, errors.New("expanded ZIP exceeds safety limit")
		}
		fileCount++

		lower := strings.ToLower(name)
		if path.Base(lower) == "backup.xml" {
			backupXML++
		}
		if !isPolicyPayload(lower) {
			continue
		}

		rc, err := zf.Open()
		if err != nil {
			return Inspection{}, err
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, io.LimitReader(rc, DefaultMaxSingleFile+1))
		closeErr := rc.Close()
		if copyErr != nil {
			return Inspection{}, copyErr
		}
		if closeErr != nil {
			return Inspection{}, closeErr
		}
		var sum [sha256.Size]byte
		copy(sum[:], h.Sum(nil))
		payload = append(payload, fileDigest{name: lower, size: zf.UncompressedSize64, hash: sum})
	}

	if backupXML == 0 {
		return Inspection{}, errors.New("no backup.xml found; expected a Microsoft GPO backup")
	}
	if len(payload) == 0 {
		return Inspection{}, errors.New("no policy payload under DomainSysvol/GPO found")
	}

	sort.Slice(payload, func(i, j int) bool { return payload[i].name < payload[j].name })
	semantic := sha256.New()
	for _, item := range payload {
		writeField(semantic, []byte(item.name))
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], item.size)
		writeField(semantic, size[:])
		writeField(semantic, item.hash[:])
	}

	return Inspection{
		ArtifactHash: hex.EncodeToString(artifact.Sum(nil)),
		SemanticHash: hex.EncodeToString(semantic.Sum(nil)),
		Size:         st.Size(),
		FileCount:    fileCount,
		PolicyFiles:  len(payload),
	}, nil
}

func writeField(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func isPolicyPayload(lower string) bool {
	return strings.Contains("/"+lower, "/domainsysvol/gpo/")
}

func cleanArchivePath(name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.ContainsRune(name, '\x00') {
		return "", errors.New("ZIP path contains NUL")
	}
	clean := path.Clean(name)
	if clean == "." || clean == "" {
		return "", nil
	}
	if strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, ":") {
		return "", fmt.Errorf("unsafe ZIP path: %q", name)
	}
	return clean, nil
}

type ExtractLimits struct {
	MaxFiles      int
	MaxExpanded   int64
	MaxSingleFile int64
}

func (l ExtractLimits) withDefaults() ExtractLimits {
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}
	if l.MaxExpanded <= 0 {
		l.MaxExpanded = DefaultMaxExpanded
	}
	if l.MaxSingleFile <= 0 {
		l.MaxSingleFile = DefaultMaxSingleFile
	}
	return l
}

func ExtractZip(filename, destination string, limits ExtractLimits) error {
	limits = limits.withDefaults()
	zr, err := zip.OpenReader(filename)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > limits.MaxFiles {
		return fmt.Errorf("ZIP has too many entries: %d", len(zr.File))
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	root, err := filepath.Abs(destination)
	if err != nil {
		return err
	}

	var total int64
	for _, zf := range zr.File {
		name, err := cleanArchivePath(zf.Name)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		if zf.UncompressedSize64 > uint64(limits.MaxSingleFile) {
			return fmt.Errorf("ZIP entry too large: %q", zf.Name)
		}
		total += int64(zf.UncompressedSize64)
		if total > limits.MaxExpanded {
			return errors.New("expanded ZIP exceeds safety limit")
		}
		if !zf.FileInfo().IsDir() && !zf.Mode().IsRegular() {
			return fmt.Errorf("unsupported ZIP entry type: %q", zf.Name)
		}

		target := filepath.Join(root, filepath.FromSlash(name))
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if absTarget != root && !strings.HasPrefix(absTarget, root+string(os.PathSeparator)) {
			return fmt.Errorf("ZIP path escapes destination: %q", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(absTarget, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(absTarget), 0o700); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(absTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, limits.MaxSingleFile+1))
		closeOutErr := out.Close()
		closeInErr := rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutErr != nil {
			return closeOutErr
		}
		if closeInErr != nil {
			return closeInErr
		}
	}
	return nil
}

// FindImportRoot locates the directory that should be passed to LGPO.exe /g.
// It accepts both a normal GPMC/Backup-GPO archive root and archives wrapped
// in one additional directory by common ZIP tools.
func FindImportRoot(extractedRoot string) (string, error) {
	root, err := filepath.Abs(extractedRoot)
	if err != nil {
		return "", err
	}
	type candidate struct {
		path  string
		depth int
	}
	var candidates []candidate
	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		depth := 0
		if rel != "." {
			depth = len(strings.Split(filepath.ToSlash(rel), "/"))
		}
		if entry.IsDir() && depth > 4 {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(entry.Name(), "manifest.xml") {
			candidates = append(candidates, candidate{path: filepath.Dir(current), depth: depth})
			return nil
		}
		if strings.EqualFold(entry.Name(), "backup.xml") {
			backupDir := filepath.Dir(current)
			candidates = append(candidates, candidate{path: backupDir, depth: depth})
			if backupDir != root {
				parent := filepath.Dir(backupDir)
				if parent == root || strings.HasPrefix(parent, root+string(os.PathSeparator)) {
					candidates = append(candidates, candidate{path: parent, depth: depth - 1})
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", errors.New("no GPO backup root found after extraction")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].depth == candidates[j].depth {
			return candidates[i].path < candidates[j].path
		}
		return candidates[i].depth < candidates[j].depth
	})
	for _, c := range candidates {
		if hasBackupAtOrBelow(c.path) {
			return c.path, nil
		}
	}
	return "", errors.New("no usable GPO backup root found")
}

func hasBackupAtOrBelow(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "backup.xml")); err == nil {
		return true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, entry.Name(), "backup.xml")); err == nil {
			return true
		}
	}
	return false
}
