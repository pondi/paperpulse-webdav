package logging

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Common errors
var (
	ErrEmptyMessage = fmt.Errorf("empty log message")
	ErrSinkWrite    = fmt.Errorf("sink write error")
)

// LogLevel represents the severity of a log entry
type LogLevel string

const (
	INFO  LogLevel = "INFO"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

// LogEntry represents a single log message with metadata.
// All fields are exported to support JSON serialization.
type LogEntry struct {
	Timestamp   time.Time      `json:"timestamp"`             // UTC timestamp when the log was created
	Level       LogLevel       `json:"level"`                 // Severity level of the log
	Message     string         `json:"message"`               // Main log message
	Fields      map[string]any `json:"fields,omitempty"`      // Additional structured data
	TraceID     string         `json:"trace_id,omitempty"`    // Optional distributed tracing ID
	Component   string         `json:"component,omitempty"`   // Optional component name for S3 logs
	Environment string         `json:"environment,omitempty"` // Optional environment for S3 logs
}

// LogSink defines the interface for log output destinations.
// Implementations must be safe for concurrent use.
type LogSink interface {
	Write(entries []LogEntry) error
	Flush() error
	Close() error
	IsImmediate() bool
}

// Logger is the main logging struct that handles log entries.
// It supports multiple sinks and buffered/immediate writing.
type Logger struct {
	sinks       []LogSink
	buffer      []LogEntry
	bufferSize  int
	bufferMutex sync.Mutex
	flushTicker *time.Ticker
	done        chan struct{}
}

const (
	defaultBufferSize    = 100
	defaultFlushInterval = 30 * time.Second
)

// NewLogger creates a new logger instance with the given sinks
func NewLogger(bufferSize int, flushInterval time.Duration, sinks ...LogSink) *Logger {
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	if flushInterval <= 0 {
		flushInterval = defaultFlushInterval
	}

	l := &Logger{
		sinks:       sinks,
		buffer:      make([]LogEntry, 0, bufferSize),
		bufferSize:  bufferSize,
		flushTicker: time.NewTicker(flushInterval),
		done:        make(chan struct{}),
	}

	go l.flushRoutine()
	return l
}

func (l *Logger) flushRoutine() {
	for {
		select {
		case <-l.flushTicker.C:
			if err := l.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing logs: %v\n", err)
			}
		case <-l.done:
			return
		}
	}
}

func (l *Logger) log(level LogLevel, msg string, fields map[string]any) {
	if msg == "" {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Message:   msg,
		Fields:    fields,
	}

	l.bufferMutex.Lock()
	defer l.bufferMutex.Unlock()

	for _, sink := range l.sinks {
		if sink.IsImmediate() {
			if err := sink.Write([]LogEntry{entry}); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to immediate sink: %v\n", err)
			}
		}
	}

	l.buffer = append(l.buffer, entry)
	if len(l.buffer) >= l.bufferSize {
		if err := l.flushBuffered(); err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing logs: %v\n", err)
		}
	}
}

func (l *Logger) flushBuffered() error {
	if len(l.buffer) == 0 {
		return nil
	}

	entries := make([]LogEntry, len(l.buffer))
	copy(entries, l.buffer)

	l.buffer = l.buffer[:0]
	l.bufferMutex.Unlock()
	defer l.bufferMutex.Lock()

	var errs []error
	for _, sink := range l.sinks {
		if !sink.IsImmediate() {
			if err := sink.Write(entries); err != nil {
				errs = append(errs, fmt.Errorf("%w: %v", ErrSinkWrite, err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sink errors: %v", errs)
	}
	return nil
}

// Flush manually flushes the log buffer
func (l *Logger) Flush() error {
	l.bufferMutex.Lock()
	defer l.bufferMutex.Unlock()
	return l.flushBuffered()
}

// Close stops the logger and flushes any remaining logs
func (l *Logger) Close() error {
	l.flushTicker.Stop()
	close(l.done)
	return l.Flush()
}

// Info logs an info message
func (l *Logger) Info(msg string, fields map[string]any) {
	l.log(INFO, msg, fields)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields map[string]any) {
	l.log(WARN, msg, fields)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields map[string]any) {
	l.log(ERROR, msg, fields)
}
