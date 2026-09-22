package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore persists rotated refresh tokens as JSON on disk.
//
// The file holds provider credentials, so it is written 0600 and replaced
// atomically: a half-written file here would cost the operator their access
// until they ran the device flow again.
type FileStore struct {
	mu     sync.Mutex
	path   string
	tokens map[string]string
}

// NewFileStore opens, or creates, a store at path.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("credential: store path cannot be empty")
	}

	s := &FileStore{path: path, tokens: make(map[string]string)}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("credential: reading %s: %w", path, err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.tokens); err != nil {
			return nil, fmt.Errorf("credential: parsing %s: %w", path, err)
		}
	}
	return s, nil
}

// Get returns the stored refresh token for a credential, if one was persisted.
// A stored token supersedes the configured one: it is the rotated value, and the
// configured one has by then been invalidated by the provider.
func (s *FileStore) Get(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, found := s.tokens[name]
	return token, found
}

// Save records a rotated refresh token.
func (s *FileStore) Save(name, refreshToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[name] = refreshToken

	data, err := json.MarshalIndent(s.tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("credential: encoding store: %w", err)
	}

	if dir := filepath.Dir(s.path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("credential: creating %s: %w", dir, err)
		}
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("credential: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("credential: replacing %s: %w", s.path, err)
	}
	return nil
}
