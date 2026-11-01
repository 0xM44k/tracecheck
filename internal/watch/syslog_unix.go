//go:build !windows

package watch

import (
	"encoding/json"
	"log/syslog"
)

// SyslogExtra returns a function that forwards alerts to the local syslog.
func SyslogExtra() (func(Alert), error) {
	w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_AUTH, "tracecheck")
	if err != nil {
		return nil, err
	}
	return func(a Alert) {
		b, _ := json.Marshal(a)
		w.Warning(string(b))
	}, nil
}
