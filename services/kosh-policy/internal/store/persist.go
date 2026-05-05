package store

import (
	"encoding/json"
	"os"
)

type policyFile struct {
	NextID   uint32   `json:"next_id"`
	Policies []Policy `json:"policies"`
}

// persistLocked writes the current state to disk. Must be called with mu held.
func (s *PolicyStore) persistLocked() {
	if s.filePath == "" {
		return
	}
	data, err := json.MarshalIndent(policyFile{NextID: s.nextID, Policies: s.policies}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.filePath, data, 0600)
}

func (s *PolicyStore) loadFromFile() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return
	}
	var f policyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	s.policies = f.Policies
	s.nextID = f.NextID
}
