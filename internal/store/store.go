package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gpo-distributor/internal/bundle"
	"gpo-distributor/internal/model"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	mu      sync.RWMutex
	root    string
	catalog model.Catalog
}

func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{root: root}
	s.catalog = model.Catalog{
		Policies: map[string]*model.Policy{},
		Profiles: map[string]*model.Profile{},
		Clients:  map[string]model.ClientReport{},
	}
	filename := filepath.Join(root, "catalog.json")
	data, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.catalog); err != nil {
			return nil, fmt.Errorf("read catalog: %w", err)
		}
	}
	if s.catalog.Policies == nil {
		s.catalog.Policies = map[string]*model.Policy{}
	}
	if s.catalog.Profiles == nil {
		s.catalog.Profiles = map[string]*model.Profile{}
	}
	if s.catalog.Clients == nil {
		s.catalog.Clients = map[string]model.ClientReport{}
	}
	return s, nil
}

func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("name must match %s", validName.String())
	}
	return nil
}

func (s *Store) ImportPolicy(name, note, sourceZip string, inspection bundle.Inspection, now time.Time, force bool) (model.PolicyVersion, bool, error) {
	if err := ValidateName(name); err != nil {
		return model.PolicyVersion{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	policy := s.catalog.Policies[name]
	if policy == nil {
		policy = &model.Policy{Name: name}
		s.catalog.Policies[name] = policy
	}
	if !force {
		for _, v := range policy.Versions {
			if v.SemanticHash == inspection.SemanticHash {
				return v, false, nil
			}
		}
	}

	versionID := fmt.Sprintf("v%s-%s", now.UTC().Format("20060102-150405"), inspection.SemanticHash[:10])
	for _, v := range policy.Versions {
		if v.Version == versionID {
			versionID = fmt.Sprintf("%s-%d", versionID, now.UnixNano()%100000)
			break
		}
	}
	rel := filepath.Join("artifacts", name, versionID+".zip")
	dst := filepath.Join(s.root, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return model.PolicyVersion{}, false, err
	}
	if err := copyFileAtomic(sourceZip, dst); err != nil {
		return model.PolicyVersion{}, false, err
	}

	v := model.PolicyVersion{
		Version:      versionID,
		CreatedAt:    now.UTC(),
		Note:         strings.TrimSpace(note),
		ArtifactPath: filepath.ToSlash(rel),
		ArtifactHash: inspection.ArtifactHash,
		SemanticHash: inspection.SemanticHash,
		Size:         inspection.Size,
		FileCount:    inspection.FileCount,
		PolicyFiles:  inspection.PolicyFiles,
	}
	policy.Versions = append(policy.Versions, v)
	if err := s.saveLocked(); err != nil {
		_ = os.Remove(dst)
		policy.Versions = policy.Versions[:len(policy.Versions)-1]
		return model.PolicyVersion{}, false, err
	}
	return v, true, nil
}

func (s *Store) ListPolicies() []model.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Policy, 0, len(s.catalog.Policies))
	for _, p := range s.catalog.Policies {
		cp := model.Policy{Name: p.Name, Versions: append([]model.PolicyVersion(nil), p.Versions...)}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) GetPolicy(name string) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.catalog.Policies[name]
	if p == nil {
		return model.Policy{}, ErrNotFound
	}
	return model.Policy{Name: p.Name, Versions: append([]model.PolicyVersion(nil), p.Versions...)}, nil
}

func (s *Store) SetProfile(name string, refs []model.ProfilePolicy, now time.Time) (model.Profile, error) {
	if err := ValidateName(name); err != nil {
		return model.Profile{}, err
	}
	if len(refs) == 0 {
		return model.Profile{}, errors.New("profile requires at least one policy")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, ref := range refs {
		if err := ValidateName(ref.Policy); err != nil {
			return model.Profile{}, fmt.Errorf("policy %q: %w", ref.Policy, err)
		}
		if seen[ref.Policy] {
			return model.Profile{}, fmt.Errorf("policy %q occurs more than once", ref.Policy)
		}
		seen[ref.Policy] = true
		p := s.catalog.Policies[ref.Policy]
		if p == nil {
			return model.Profile{}, fmt.Errorf("policy %q: %w", ref.Policy, ErrNotFound)
		}
		if ref.Version == "" {
			ref.Version = "latest"
		}
		if ref.Version != "latest" && !hasVersion(p, ref.Version) {
			return model.Profile{}, fmt.Errorf("policy %q version %q: %w", ref.Policy, ref.Version, ErrNotFound)
		}
	}
	cp := append([]model.ProfilePolicy(nil), refs...)
	for i := range cp {
		if cp[i].Version == "" {
			cp[i].Version = "latest"
		}
	}
	profile := &model.Profile{Name: name, Policies: cp, UpdatedAt: now.UTC()}
	s.catalog.Profiles[name] = profile
	if err := s.saveLocked(); err != nil {
		return model.Profile{}, err
	}
	return *profile, nil
}

func (s *Store) ListProfiles() []model.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Profile, 0, len(s.catalog.Profiles))
	for _, p := range s.catalog.Profiles {
		out = append(out, model.Profile{Name: p.Name, Policies: append([]model.ProfilePolicy(nil), p.Policies...), UpdatedAt: p.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) ResolveManifest(profileName string) (model.Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile := s.catalog.Profiles[profileName]
	if profile == nil {
		return model.Manifest{}, ErrNotFound
	}
	manifest := model.Manifest{Profile: profile.Name, ProfileUpdated: profile.UpdatedAt}
	for _, ref := range profile.Policies {
		policy := s.catalog.Policies[ref.Policy]
		if policy == nil || len(policy.Versions) == 0 {
			return model.Manifest{}, fmt.Errorf("policy %q has no versions", ref.Policy)
		}
		var selected model.PolicyVersion
		if ref.Version == "latest" || ref.Version == "" {
			selected = policy.Versions[len(policy.Versions)-1]
		} else {
			found := false
			for _, v := range policy.Versions {
				if v.Version == ref.Version {
					selected = v
					found = true
					break
				}
			}
			if !found {
				return model.Manifest{}, fmt.Errorf("policy %q version %q missing", ref.Policy, ref.Version)
			}
		}
		manifest.Policies = append(manifest.Policies, model.ResolvedPolicy{
			Name: ref.Policy, Version: selected.Version, SHA256: selected.ArtifactHash,
			SemanticHash: selected.SemanticHash, Size: selected.Size,
			DownloadURL: fmt.Sprintf("/api/v1/artifacts/%s/%s", ref.Policy, selected.Version),
		})
	}
	gen, err := generationHash(manifest)
	if err != nil {
		return model.Manifest{}, err
	}
	manifest.Generation = gen
	return manifest, nil
}

func generationHash(m model.Manifest) (string, error) {
	m.Generation = ""
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (s *Store) Artifact(name, version string) (model.PolicyVersion, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.catalog.Policies[name]
	if p == nil {
		return model.PolicyVersion{}, "", ErrNotFound
	}
	for _, v := range p.Versions {
		if v.Version == version {
			return v, filepath.Join(s.root, filepath.FromSlash(v.ArtifactPath)), nil
		}
	}
	return model.PolicyVersion{}, "", ErrNotFound
}

func (s *Store) PutClientReport(report model.ClientReport) error {
	if report.ClientID == "" {
		return errors.New("client_id is required")
	}
	if len(report.ClientID) > 128 {
		return errors.New("client_id is too long")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.catalog.Clients[report.ClientID] = report
	return s.saveLocked()
}

func (s *Store) ListClientReports() []model.ClientReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ClientReport, 0, len(s.catalog.Clients))
	for _, r := range s.catalog.Clients {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReportedAt.After(out[j].ReportedAt) })
	return out
}

func (s *Store) DeletePolicy(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	policy := s.catalog.Policies[name]
	if policy == nil {
		return ErrNotFound
	}
	for _, profile := range s.catalog.Profiles {
		for _, ref := range profile.Policies {
			if ref.Policy == name {
				return fmt.Errorf("policy %q is used by profile %q: %w", name, profile.Name, ErrConflict)
			}
		}
	}

	artifactDir := filepath.Join(s.root, "artifacts", name)
	tomb := artifactDir + fmt.Sprintf(".delete-%d", time.Now().UnixNano())
	renamed := false
	if _, err := os.Stat(artifactDir); err == nil {
		if err := os.Rename(artifactDir, tomb); err != nil {
			return err
		}
		renamed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	delete(s.catalog.Policies, name)
	if err := s.saveLocked(); err != nil {
		s.catalog.Policies[name] = policy
		if renamed {
			_ = os.Rename(tomb, artifactDir)
		}
		return err
	}
	if renamed {
		_ = os.RemoveAll(tomb)
	}
	return nil
}

func (s *Store) DeletePolicyVersion(name, version string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := ValidateName(version); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	policy := s.catalog.Policies[name]
	if policy == nil {
		return ErrNotFound
	}
	if len(policy.Versions) <= 1 {
		return fmt.Errorf("cannot delete the last version of policy %q; delete the policy instead: %w", name, ErrConflict)
	}
	index := -1
	var selected model.PolicyVersion
	for i, candidate := range policy.Versions {
		if candidate.Version == version {
			index = i
			selected = candidate
			break
		}
	}
	if index < 0 {
		return ErrNotFound
	}
	for _, profile := range s.catalog.Profiles {
		for _, ref := range profile.Policies {
			if ref.Policy == name && ref.Version == version {
				return fmt.Errorf("policy %q version %q is pinned by profile %q: %w", name, version, profile.Name, ErrConflict)
			}
		}
	}

	artifactPath := filepath.Join(s.root, filepath.FromSlash(selected.ArtifactPath))
	tomb := artifactPath + fmt.Sprintf(".delete-%d", time.Now().UnixNano())
	renamed := false
	if _, err := os.Stat(artifactPath); err == nil {
		if err := os.Rename(artifactPath, tomb); err != nil {
			return err
		}
		renamed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	original := append([]model.PolicyVersion(nil), policy.Versions...)
	policy.Versions = append(policy.Versions[:index], policy.Versions[index+1:]...)
	if err := s.saveLocked(); err != nil {
		policy.Versions = original
		if renamed {
			_ = os.Rename(tomb, artifactPath)
		}
		return err
	}
	if renamed {
		_ = os.Remove(tomb)
	}
	return nil
}

func (s *Store) DeleteProfile(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.catalog.Profiles[name]
	if profile == nil {
		return ErrNotFound
	}
	delete(s.catalog.Profiles, name)
	if err := s.saveLocked(); err != nil {
		s.catalog.Profiles[name] = profile
		return err
	}
	return nil
}

func (s *Store) DeleteClientReport(clientID string) error {
	if strings.TrimSpace(clientID) == "" || len(clientID) > 128 {
		return errors.New("invalid client id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report, ok := s.catalog.Clients[clientID]
	if !ok {
		return ErrNotFound
	}
	delete(s.catalog.Clients, clientID)
	if err := s.saveLocked(); err != nil {
		s.catalog.Clients[clientID] = report
		return err
	}
	return nil
}

func hasVersion(p *model.Policy, version string) bool {
	for _, v := range p.Versions {
		if v.Version == version {
			return true
		}
	}
	return false
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.catalog, "", "  ")
	if err != nil {
		return err
	}
	filename := filepath.Join(s.root, "catalog.json")
	tmp := filename + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filename)
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmp)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
