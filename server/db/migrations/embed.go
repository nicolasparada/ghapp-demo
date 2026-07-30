package migrations

import "embed"

// FS contains all forward-only SQL migrations for the control-plane.
//
//go:embed *.sql
var FS embed.FS
