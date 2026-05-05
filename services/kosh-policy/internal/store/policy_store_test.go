package store_test

import (
	"testing"
	"github.com/kosh/policy/internal/store"
)

func TestValidateMandatoryParty(t *testing.T) {
	ps := store.NewPolicyStore("")
	ps.Add(store.Policy{
		Name:             "cfo-required",
		TxTag:            "treasury",
		MandatoryParties: []uint32{2},
		MinThreshold:     2,
	})

	// Missing party 2
	v := ps.Validate("treasury", []uint32{1, 3})
	if v == nil {
		t.Fatal("expected violation, got nil")
	}
	t.Logf("violation: %s", v.Message)

	// Party 2 present
	v = ps.Validate("treasury", []uint32{1, 2})
	if v != nil {
		t.Fatalf("expected no violation, got: %s", v.Message)
	}
}

func TestValidateMinThreshold(t *testing.T) {
	ps := store.NewPolicyStore("")
	ps.Add(store.Policy{Name: "min2", MinThreshold: 2})

	v := ps.Validate("any", []uint32{1})
	if v == nil {
		t.Fatal("expected min threshold violation")
	}
}
