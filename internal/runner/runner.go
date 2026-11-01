// Package runner wraps command execution so every collector and canary can be
// tested with a fake runner and the real one stays tiny.
package runner

import (
	"bytes"
	"context"
	"os/exec"
)

// Runner runs an external command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Real executes commands on the host. It never uses a shell.
type Real struct{}

func (Real) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// Have reports whether a program is on PATH.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Call records one invocation made through a Fake.
type Call struct {
	Name string
	Args []string
}

// Fake returns canned output keyed by "name arg1 arg2..." and records calls.
type Fake struct {
	Out   map[string]string
	Err   map[string]error
	Calls []Call
}

func key(name string, args []string) string {
	k := name
	for _, a := range args {
		k += " " + a
	}
	return k
}

func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, Call{name, append([]string(nil), args...)})
	k := key(name, args)
	if e, ok := f.Err[k]; ok {
		return []byte(f.Out[k]), e
	}
	return []byte(f.Out[k]), nil
}
