package config

import (
	"errors"
	"fmt"
)

// ErrFormat is the sentinel matching Python's ConfigFormatError
// (srxtool.py L105). Testable via errors.Is; structured detail is
// accessible via errors.As on *FormatError.
var ErrFormat = errors.New("unrecognized configuration format")

// ErrTooLarge is returned when the input exceeds Options.MaxBytes. The
// limit is applied BEFORE any parsing (cf task 01, security section).
var ErrTooLarge = errors.New("configuration too large")

// FormatError precisely describes why an input was rejected. The message
// stays generic in terms of user content: it never echoes back a snippet
// of the input, so as not to turn an error message into a reflection
// channel (cf cross-cutting principles, MD 00).
type FormatError struct {
	// Reason: short, stable cause, usable as-is on the API side.
	Reason string
	// Line: offending line number when known (0 otherwise).
	Line int
	// Format: format attempted ("xml", "curly", "set", "" if none).
	Format string
}

func (e *FormatError) Error() string {
	switch {
	case e.Line > 0 && e.Format != "":
		return fmt.Sprintf("%s (format %s, line %d): %s", ErrFormat.Error(), e.Format, e.Line, e.Reason)
	case e.Format != "":
		return fmt.Sprintf("%s (format %s): %s", ErrFormat.Error(), e.Format, e.Reason)
	default:
		return fmt.Sprintf("%s: %s", ErrFormat.Error(), e.Reason)
	}
}

// Unwrap enables errors.Is(err, ErrFormat).
func (e *FormatError) Unwrap() error { return ErrFormat }

func formatErr(format, reason string, line int) error {
	return &FormatError{Reason: reason, Line: line, Format: format}
}
