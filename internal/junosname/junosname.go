// Package junosname carries q() and validate_new_name() (srxtool.py
// L898-936), used identically by srxaudit.py (direct import) and
// srxtool.py. Same sharing here: internal/audit and internal/rules
// import this package rather than duplicating the validation — exactly
// the kind of duplication the rewrite is meant to eliminate.
package junosname

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrUnsafeName: port of UnsafeNameError (srxtool.py L920). A name coming
// from the configuration (or entered by an operator in a CSV) that
// contains a character allowing an instruction to be injected into a
// generated set/delete command must abort the operation, not produce a
// dangerous fix.
var ErrUnsafeName = errors.New("name rejected")

// UnsafeNameError gives the detail, never echoed back into a generic
// message on the API side (see cross-cutting principles, MD 00).
type UnsafeNameError struct {
	Name   string
	Reason string
}

func (e *UnsafeNameError) Error() string { return fmt.Sprintf("%s: %s", ErrUnsafeName, e.Reason) }
func (e *UnsafeNameError) Unwrap() error { return ErrUnsafeName }

// safeNameRE / nameInjectionRE: exact ports of _SAFE_NAME_RE and
// _NAME_INJECTION_RE (srxtool.py L903-908).
var (
	safeNameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,62}$`)
	nameInjectionRE = regexp.MustCompile(`[\r\n;{}]`)
)

// Quote: port of q() (srxtool.py L910-925). Defensively quotes a name
// coming from the configuration before inserting it into a generated
// set/delete command.
//
// An empty string corresponds to Python's `None` (`q(None) == '""'`).
func Quote(name string) (string, error) {
	if name == "" {
		return `""`, nil
	}
	if nameInjectionRE.MatchString(name) {
		return "", &UnsafeNameError{Name: name, Reason: "contains a newline, ';', or a brace, " +
			"which would inject an instruction into the generated command"}
	}
	if safeNameRE.MatchString(name) {
		return name, nil
	}
	escaped := strings.ReplaceAll(name, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`, nil
}

// ValidateNewName: port of validate_new_name() (srxtool.py L928-936).
// Unlike Quote, rejects anything that isn't a plain identifier: this
// name is meant to be loaded onto the firewall, this isn't the place to
// accept anything exotic. context is appended to the error message
// (e.g. " (CSV line 3)").
func ValidateNewName(name, context string) (string, error) {
	if !safeNameRE.MatchString(name) {
		return "", &UnsafeNameError{Name: name, Reason: fmt.Sprintf(
			"invalid 'new_name'%s: %q. Expected: 1 to 63 characters among "+
				"[A-Za-z0-9_.:/@+-], starting with a letter or a digit.", context, name)}
	}
	return name, nil
}
