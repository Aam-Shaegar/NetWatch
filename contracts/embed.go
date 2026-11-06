package contracts

import "embed"

// Schemas is the structural source of truth used by the Go validator.
//
//go:embed *.schema.json
var Schemas embed.FS
