package handler

import (
	"encoding/json"
	"testing"
)

func TestConvertLineageTreeToView(t *testing.T) {
	t.Parallel()

	roots := []lineageTreePayload{
		{
			NodeType:     "process",
			PID:          1,
			Name:         "systemd",
			DirectEgress: 0,
			TotalEgress:  3,
			Children: []lineageTreePayload{
				{
					NodeType:     "process",
					PID:          20,
					Name:         "python3.12",
					Cmdline:      "/usr/bin/python3.12 /work/script.py",
					DirectEgress: 3,
					TotalEgress:  3,
					Egress: []lineageEgressPayload{
						{
							NodeType:    "egress",
							Destination: "127.0.0.53",
							Port:        53,
							Count:       1,
						},
						{
							NodeType:    "egress",
							Destination: "httpbingo.org",
							Port:        443,
							Count:       2,
						},
					},
				},
			},
		},
	}

	view := convertLineageTreeToView(roots)
	if len(view) != 1 {
		t.Fatalf("expected one root view node, got %d", len(view))
	}

	root := view[0]
	if root.Label != "systemd" {
		t.Fatalf("unexpected root label: %q", root.Label)
	}
	if len(root.Children) != 1 {
		t.Fatalf("expected one child, got %d", len(root.Children))
	}

	child := root.Children[0]
	if child.Label != "script.py" {
		t.Fatalf("expected script.py label from cmdline, got %q", child.Label)
	}
	if len(child.Egress) != 2 {
		t.Fatalf("expected 2 egress leaves, got %d", len(child.Egress))
	}
	if child.Egress[0].Target != "localhost (dns resolver)" {
		t.Fatalf("unexpected dns target label: %q", child.Egress[0].Target)
	}
	if child.Egress[1].Target != "httpbingo.org" {
		t.Fatalf("unexpected egress target label: %q", child.Egress[1].Target)
	}
	if child.Egress[1].Count != 2 {
		t.Fatalf("unexpected egress count: %d", child.Egress[1].Count)
	}
}

func TestValidateRunSummaryPayload(t *testing.T) {
	t.Parallel()

	good := map[string]any{
		"schema_version":  "v2",
		"capture_backend": "bpftrace:sudo:connect-v4v6",
		"lineage_tree":    []any{},
	}
	goodJSON, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("marshal good payload: %v", err)
	}
	if err := validateRunSummaryPayload(goodJSON); err != nil {
		t.Fatalf("validate good payload: %v", err)
	}

	bad := map[string]any{
		"schema_version": "v1",
		"events":         []any{},
	}
	badJSON, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("marshal bad payload: %v", err)
	}
	if err := validateRunSummaryPayload(badJSON); err == nil {
		t.Fatal("expected validation error for non-v2 payload")
	}
}
