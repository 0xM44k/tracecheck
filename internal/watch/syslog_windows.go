//go:build windows

package watch

import "errors"

// SyslogExtra is not available on Windows.
func SyslogExtra() (func(Alert), error) { return nil, errors.New("syslog is not available on Windows") }
