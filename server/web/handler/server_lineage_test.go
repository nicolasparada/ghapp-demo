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

	view := convertLineageTreeToView(roots, true)
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

func TestConfiguredGitHubAppSettingsURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		settingsURL string
		installURL  string
		want        string
	}{
		{name: "both empty", settingsURL: "", installURL: "", want: "https://github.com/apps"},
		{name: "settings preferred", settingsURL: "https://github.com/apps/ghapp-demo-app", installURL: "https://github.com/apps/ghapp-demo-app/installations/new", want: "https://github.com/apps/ghapp-demo-app"},
		{name: "fallback to install url as-is", settingsURL: "", installURL: "https://github.com/apps/ghapp-demo-app/installations/new", want: "https://github.com/apps/ghapp-demo-app/installations/new"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := configuredGitHubAppSettingsURL(tc.settingsURL, tc.installURL)
			if got != tc.want {
				t.Fatalf("configuredGitHubAppSettingsURL(%q, %q) = %q, want %q", tc.settingsURL, tc.installURL, got, tc.want)
			}
		})
	}
}

func TestConvertLineageTreeToView_PublicHidesCmdlineDerivedLabels(t *testing.T) {
	t.Parallel()

	roots := []lineageTreePayload{
		{
			NodeType: "process",
			PID:      42,
			Name:     "python3.12",
			Cmdline:  "/usr/bin/python3.12 /work/script.py",
		},
	}

	view := convertLineageTreeToView(roots, false)
	if len(view) != 1 {
		t.Fatalf("expected one root view node, got %d", len(view))
	}
	if view[0].Label != "python3.12" {
		t.Fatalf("expected process name label in public mode, got %q", view[0].Label)
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
