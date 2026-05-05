package bb

import (
	"testing"
	"time"
)

func TestPostRead(t *testing.T) {
	s := NewStore()
	s.Post("topic1", "hello")
	v, ok := s.Read("topic1")
	if !ok || v != "hello" {
		t.Fatalf("expected hello, got %q ok=%v", v, ok)
	}
}

func TestSubscribeReceivesValue(t *testing.T) {
	s := NewStore()
	ch := s.Subscribe("topic2")
	s.Post("topic2", "world")

	select {
	case v := <-ch:
		if v != "world" {
			t.Fatalf("expected world, got %q", v)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for value")
	}
}

func TestClear(t *testing.T) {
	s := NewStore()
	s.Post("a", "1")
	s.Post("b", "2")
	n := s.Clear()
	if n != 2 {
		t.Fatalf("expected 2 cleared, got %d", n)
	}
	_, ok := s.Read("a")
	if ok {
		t.Fatal("expected key to be gone after clear")
	}
}
