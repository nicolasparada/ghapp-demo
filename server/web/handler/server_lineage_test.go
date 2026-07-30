package handler

import (
	"encoding/json"
	"testing"
)

func TestRenderLineageTreeLines(t *testing.T) {
	t.Parallel()

	roots := []lineageTreePayload{
		{
			NodeType: "process",
			PID:      1,
			Name:     "systemd",
			Children: []lineageTreePayload{
				{
					NodeType: "process",
					PID:      20,
					Name:     "containerd-shim-runc-v2",
					Children: []lineageTreePayload{
						{
							NodeType: "process",
							PID:      30,
							Name:     "run-simulations",
							Egress: []lineageEgressPayload{
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
				{
					NodeType: "process",
					PID:      40,
					Name:     "hosted-compute-agent",
					Egress: []lineageEgressPayload{
						{
							NodeType:    "egress",
							Destination: "127.0.0.53",
							Port:        53,
							Count:       1,
						},
					},
				},
			},
		},
	}

	got := renderLineageTreeLines("workflow · job", roots)
	want := []string{
		"workflow · job",
		"└─ systemd",
		"   ├─ containerd-shim-runc-v2",
		"   │  └─ run-simulations",
		"   │     └─ → httpbingo.org ×2",
		"   └─ hosted-compute-agent",
		"      └─ → localhost (dns resolver)",
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected line count: got=%d want=%d\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d mismatch: got=%q want=%q", i, got[i], want[i])
		}
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
