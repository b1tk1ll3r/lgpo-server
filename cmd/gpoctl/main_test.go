package main

import "testing"

func TestValidateRepositoryName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		ok    bool
	}{
		{name: "simple", value: "windows-firewall", ok: true},
		{name: "dots and underscores", value: "MSFT.Server_2022", ok: true},
		{name: "space", value: "Server Windows Firewall", ok: false},
		{name: "umlaut", value: "server-härtung", ok: false},
		{name: "leading hyphen", value: "-server", ok: false},
		{name: "too long", value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryName("test", tt.value)
			if tt.ok && err != nil {
				t.Fatalf("expected valid name, got %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected invalid name")
			}
		})
	}
}
