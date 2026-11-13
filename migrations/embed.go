package migrations

import "embed"

// Files contains immutable migration pairs; applied checksums are stored in PostgreSQL.
//
//go:embed *.sql
var Files embed.FS
