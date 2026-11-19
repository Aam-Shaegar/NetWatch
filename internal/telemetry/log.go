package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a logger for one process with stable JSON fields.
func NewLogger(component string) *slog.Logger {
	level := slog.LevelInfo
	if configured := strings.ToUpper(os.Getenv("NETWATCH_LOG_LEVEL")); configured != "" {
		if configured == "WARNING" {
			configured = "WARN"
		}
		if err := level.UnmarshalText([]byte(configured)); err != nil {
			level = slog.LevelInfo
		}
	}
	version := os.Getenv("NETWATCH_BUILD_VERSION")
	if version == "" {
		version = "dev"
	}
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) != 0 {
				return attr
			}
			switch attr.Key {
			case slog.TimeKey:
				return slog.Time(slog.TimeKey, attr.Value.Time().UTC())
			case slog.MessageKey:
				attr.Key = "event"
			}
			return attr
		},
	})
	return slog.New(handler).With("component", component, "version", version)
}
