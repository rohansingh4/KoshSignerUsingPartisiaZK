package store

import (
	"fmt"
	"sync"
	"time"
)

type Policy struct {
	ID               uint32   `json:"id"`
	Name             string   `json:"name"`
	TxTag            string   `json:"tx_tag"`
	MandatoryParties []uint32 `json:"mandatory_parties"`
	MinThreshold     uint32   `json:"min_threshold"`
	CreatedAt        string   `json:"created_at"`
}

type PolicyViolation struct {
	PolicyName     string
	MissingParties []uint32
	Message        string
}

// PolicyStore is a thread-safe in-memory policy store with optional file persistence.
type PolicyStore struct {
	mu       sync.RWMutex
	policies []Policy
	nextID   uint32
	filePath string
}

func NewPolicyStore(filePath string) *PolicyStore {
	ps := &PolicyStore{filePath: filePath, nextID: 1}
	if filePath != "" {
		ps.loadFromFile()
	}
	return ps
}

func (s *PolicyStore) Add(p Policy) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.ID = s.nextID
	s.nextID++
	p.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.policies = append(s.policies, p)
	s.persistLocked()
	return p.ID
}

func (s *PolicyStore) Remove(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.policies {
		if p.ID == id {
			s.policies = append(s.policies[:i], s.policies[i+1:]...)
			s.persistLocked()
			return true
		}
	}
	return false
}

func (s *PolicyStore) List() []Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, len(s.policies))
	copy(out, s.policies)
	return out
}

// Validate checks all policies for tx_tag match. Returns the first violation found.
func (s *PolicyStore) Validate(txTag string, signingParties []uint32) *PolicyViolation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	partySet := make(map[uint32]bool, len(signingParties))
	for _, p := range signingParties {
		partySet[p] = true
	}

	for _, pol := range s.policies {
		// Only apply policies whose tx_tag matches (empty tx_tag = applies to all)
		if pol.TxTag != "" && pol.TxTag != txTag {
			continue
		}
		if uint32(len(signingParties)) < pol.MinThreshold {
			return &PolicyViolation{
				PolicyName: pol.Name,
				Message:    fmt.Sprintf("policy '%s': need %d signers, got %d", pol.Name, pol.MinThreshold, len(signingParties)),
			}
		}
		var missing []uint32
		for _, m := range pol.MandatoryParties {
			if !partySet[m] {
				missing = append(missing, m)
			}
		}
		if len(missing) > 0 {
			return &PolicyViolation{
				PolicyName:     pol.Name,
				MissingParties: missing,
				Message:        fmt.Sprintf("policy '%s': mandatory parties %v are missing from signing set", pol.Name, missing),
			}
		}
	}
	return nil
}
