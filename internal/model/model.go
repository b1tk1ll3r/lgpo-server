package model

import "time"

type PolicyVersion struct {
	Version      string    `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	Note         string    `json:"note,omitempty"`
	ArtifactPath string    `json:"artifact_path"`
	ArtifactHash string    `json:"artifact_sha256"`
	SemanticHash string    `json:"semantic_sha256"`
	Size         int64     `json:"size"`
	FileCount    int       `json:"file_count"`
	PolicyFiles  int       `json:"policy_file_count"`
}

type Policy struct {
	Name     string          `json:"name"`
	Versions []PolicyVersion `json:"versions"`
}

type ProfilePolicy struct {
	Policy  string `json:"policy"`
	Version string `json:"version"` // "latest" or an exact version
}

type Profile struct {
	Name      string          `json:"name"`
	Policies  []ProfilePolicy `json:"policies"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type ResolvedPolicy struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
	SemanticHash string `json:"semantic_sha256"`
	Size         int64  `json:"size"`
	DownloadURL  string `json:"download_url"`
}

type Manifest struct {
	Profile        string           `json:"profile"`
	ProfileUpdated time.Time        `json:"profile_updated_at"`
	Generation     string           `json:"generation"`
	Policies       []ResolvedPolicy `json:"policies"`
}

type ClientReport struct {
	ClientID        string    `json:"client_id"`
	Hostname        string    `json:"hostname,omitempty"`
	Profile         string    `json:"profile"`
	Generation      string    `json:"generation,omitempty"`
	Success         bool      `json:"success"`
	Message         string    `json:"message,omitempty"`
	AgentVersion    string    `json:"agent_version,omitempty"`
	ReportedAt      time.Time `json:"reported_at"`
	AppliedAt       time.Time `json:"applied_at,omitempty"`
	OperatingSystem string    `json:"operating_system,omitempty"`
}

type Catalog struct {
	Policies map[string]*Policy      `json:"policies"`
	Profiles map[string]*Profile     `json:"profiles"`
	Clients  map[string]ClientReport `json:"clients"`
}
