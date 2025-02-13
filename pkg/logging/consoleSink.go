package logging

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Common errors for console sink
var (
	ErrConsoleWrite = fmt.Errorf("console write error")
)

// ConsoleSink implements LogSink interface for writing human-readable logs to the console.
type ConsoleSink struct {
	writer io.Writer
	mutex  sync.Mutex
}

// NewConsoleSink creates a new console sink that writes to stdout.
func NewConsoleSink() *ConsoleSink {
	return &ConsoleSink{
		writer: os.Stdout,
	}
}

// IsImmediate implements LogSink interface
func (s *ConsoleSink) IsImmediate() bool {
	return true
}

// ANSI color codes for log level formatting
const (
	colorReset = "\033[0m"
	colorInfo  = "\033[32m" // Green
	colorWarn  = "\033[33m" // Yellow
	colorError = "\033[31m" // Red
)

// formatLevel returns a colored string representation of the log level
func formatLevel(level LogLevel) string {
	var color string
	switch level {
	case INFO:
		color = colorInfo
	case WARN:
		color = colorWarn
	case ERROR:
		color = colorError
	default:
		return string(level)
	}
	return fmt.Sprintf("%s%s%s", color, level, colorReset)
}

// priorityFields defines the order of important fields in console output
var priorityFields = []string{
	"trace_id",
	"request_id",
	"method",
	"path",
	"status",
	"duration_ms",
	"username",
	"error",
}

// formatFields formats the fields in a human-readable way with consistent ordering
func formatFields(fields map[string]any) string {
	if len(fields) == 0 {
		return ""
	}

	var parts []string
	seen := make(map[string]bool)

	// Add priority fields first
	for _, key := range priorityFields {
		if value, ok := fields[key]; ok {
			parts = append(parts, formatField(key, value))
			seen[key] = true
		}
	}

	// Add remaining fields in alphabetical order
	var remaining []string
	for key := range fields {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)

	for _, key := range remaining {
		parts = append(parts, formatField(key, fields[key]))
	}

	return strings.Join(parts, " ")
}

// formatField formats a single field with proper escaping
func formatField(key string, value any) string {
	switch v := value.(type) {
	case string:
		if strings.Contains(v, " ") {
			return fmt.Sprintf("%s=%q", key, v)
		}
		return fmt.Sprintf("%s=%s", key, v)
	case error:
		return fmt.Sprintf("%s=%q", key, v.Error())
	default:
		return fmt.Sprintf("%s=%v", key, v)
	}
}

// Write implements LogSink interface
func (s *ConsoleSink) Write(entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, entry := range entries {
		line := fmt.Sprintf("%s [%s] %s %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05.000"),
			formatLevel(entry.Level),
			entry.Message,
			formatFields(entry.Fields),
		)

		if _, err := s.writer.Write([]byte(line)); err != nil {
			return fmt.Errorf("%w: %v", ErrConsoleWrite, err)
		}
	}
	return nil
}

// Flush implements LogSink interface
func (s *ConsoleSink) Flush() error {
	if f, ok := s.writer.(interface{ Sync() error }); ok {
		return f.Sync()
	}
	return nil
}

// Close implements LogSink interface
func (s *ConsoleSink) Close() error {
	return nil
}
