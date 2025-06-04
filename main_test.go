package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		port     string
		keyType  string
		wantHost string
		wantPort string
		wantUser string
		wantType string
		wantErr  bool
	}{
		{
			name:     "basic user@host with ed25519",
			target:   "alice@example.com",
			port:     "22",
			keyType:  "ed25519",
			wantHost: "example.com",
			wantPort: "22",
			wantUser: "alice",
			wantType: "ed25519",
			wantErr:  false,
		},
		{
			name:     "user@host:port with rsa",
			target:   "bob@server.local:2222",
			port:     "22",
			keyType:  "rsa",
			wantHost: "server.local",
			wantPort: "2222",
			wantUser: "bob",
			wantType: "rsa",
			wantErr:  false,
		},
		{
			name:     "custom port flag with ecdsa",
			target:   "charlie@host.com",
			port:     "3333",
			keyType:  "ecdsa",
			wantHost: "host.com",
			wantPort: "3333",
			wantUser: "charlie",
			wantType: "ecdsa",
			wantErr:  false,
		},
		{
			name:    "invalid format - no @",
			target:  "invalidtarget",
			port:    "22",
			keyType: "ed25519",
			wantErr: true,
		},
		{
			name:    "invalid format - empty user",
			target:  "@hostname",
			port:    "22",
			keyType: "ed25519",
			wantErr: true,
		},
		{
			name:    "invalid format - empty host",
			target:  "user@",
			port:    "22",
			keyType: "ed25519",
			wantErr: true,
		},
		{
			name:    "invalid key type",
			target:  "user@host",
			port:    "22",
			keyType: "dsa",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseTarget(tt.target, tt.port, tt.keyType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseTarget() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseTarget() unexpected error: %v", err)
				return
			}

			if config.Host != tt.wantHost {
				t.Errorf("parseTarget() host = %v, want %v", config.Host, tt.wantHost)
			}

			if config.Port != tt.wantPort {
				t.Errorf("parseTarget() port = %v, want %v", config.Port, tt.wantPort)
			}

			if config.Username != tt.wantUser {
				t.Errorf("parseTarget() username = %v, want %v", config.Username, tt.wantUser)
			}

			if config.KeyType != tt.wantType {
				t.Errorf("parseTarget() keyType = %v, want %v", config.KeyType, tt.wantType)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	// Create temporary file
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "existing")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "existing file",
			path: existingFile,
			want: true,
		},
		{
			name: "non-existing file",
			path: filepath.Join(tmpDir, "nonexistent"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fileExists(tt.path); got != tt.want {
				t.Errorf("fileExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureSSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	sshDir := filepath.Join(tmpDir, ".ssh")

	// Test creating new directory
	if err := ensureSSHDir(sshDir); err != nil {
		t.Errorf("ensureSSHDir() error = %v", err)
	}

	// Check directory exists
	if !fileExists(sshDir) {
		t.Error("ensureSSHDir() failed to create directory")
	}

	// Check permissions
	info, err := os.Stat(sshDir)
	if err != nil {
		t.Fatalf("Failed to stat directory: %v", err)
	}

	if info.Mode().Perm() != 0700 {
		t.Errorf("ensureSSHDir() permissions = %o, want 0700", info.Mode().Perm())
	}
}

func TestGenerateKeyPair(t *testing.T) {
	keyTypes := []struct {
		name      string
		keyType   string
		keyPrefix string
	}{
		{"ed25519", "ed25519", "ssh-ed25519"},
		{"rsa", "rsa", "ssh-rsa"},
		{"ecdsa", "ecdsa", "ecdsa-sha2-nistp256"},
	}

	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			privateKeyPath := filepath.Join(tmpDir, "test_key")
			publicKeyPath := privateKeyPath + ".pub"

			err := generateKeyPair(privateKeyPath, publicKeyPath, kt.keyType)
			if err != nil {
				t.Errorf("generateKeyPair() error = %v", err)
			}

			// Check both files exist
			if !fileExists(privateKeyPath) {
				t.Error("generateKeyPair() failed to create private key")
			}

			if !fileExists(publicKeyPath) {
				t.Error("generateKeyPair() failed to create public key")
			}

			// Check private key permissions
			privInfo, err := os.Stat(privateKeyPath)
			if err != nil {
				t.Fatalf("Failed to stat private key: %v", err)
			}

			if privInfo.Mode().Perm() != 0600 {
				t.Errorf("generateKeyPair() private key permissions = %o, want 0600", privInfo.Mode().Perm())
			}

			// Check public key permissions
			pubInfo, err := os.Stat(publicKeyPath)
			if err != nil {
				t.Fatalf("Failed to stat public key: %v", err)
			}

			if pubInfo.Mode().Perm() != 0644 {
				t.Errorf("generateKeyPair() public key permissions = %o, want 0644", pubInfo.Mode().Perm())
			}

			// Verify key content is valid
			pubKeyData, err := os.ReadFile(publicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read public key: %v", err)
			}

			if len(pubKeyData) == 0 {
				t.Error("generateKeyPair() created empty public key")
			}

			// Check it starts with the expected key type
			pubKeyStr := string(pubKeyData)
			if !strings.HasPrefix(pubKeyStr, kt.keyPrefix) {
				t.Errorf("generateKeyPair() public key doesn't start with %s, got: %s", kt.keyPrefix, pubKeyStr[:min(len(pubKeyStr), 30)])
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
