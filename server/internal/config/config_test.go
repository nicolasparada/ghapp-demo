package config

import "testing"

func TestParseCSVAllowlist(t *testing.T) {
	t.Parallel()

	got := parseCSVAllowlist(" https://a.example ,https://b.example,,https://a.example ")
	if len(got) != 2 {
		t.Fatalf("expected 2 audiences, got %d (%v)", len(got), got)
	}
	if got[0] != "https://a.example" || got[1] != "https://b.example" {
		t.Fatalf("unexpected audiences: %v", got)
	}
}

func TestParseCSVAllowlist_Empty(t *testing.T) {
	t.Parallel()

	got := parseCSVAllowlist(" , , ")
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}
