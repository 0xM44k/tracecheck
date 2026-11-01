//go:build linux

package watch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type proc struct {
	PID, PPID, UID int
	Comm, Exe, Cmd string
}

func describe(pid int) proc {
	p := proc{PID: pid}
	base := "/proc/" + strconv.Itoa(pid)
	if b, err := os.ReadFile(base + "/comm"); err == nil {
		p.Comm = strings.TrimSpace(string(b))
	}
	p.Exe, _ = os.Readlink(base + "/exe")
	if b, err := os.ReadFile(base + "/cmdline"); err == nil {
		p.Cmd = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		if len(p.Cmd) > 300 {
			p.Cmd = p.Cmd[:300] + "…"
		}
	}
	if b, err := os.ReadFile(base + "/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				if f := strings.Fields(l); len(f) > 1 {
					p.UID, _ = strconv.Atoi(f[1])
				}
			}
			if strings.HasPrefix(l, "PPid:") {
				if f := strings.Fields(l); len(f) > 1 {
					p.PPID, _ = strconv.Atoi(f[1])
				}
			}
		}
	}
	return p
}

// chain returns up to n ancestors of pid as "pid:comm", nearest first.
func chain(pid, n int) ([]string, map[int]bool) {
	var out []string
	anc := map[int]bool{}
	cur := describe(pid).PPID
	for i := 0; i < n && cur > 0; i++ {
		d := describe(cur)
		out = append(out, fmt.Sprintf("%d:%s", cur, d.Comm))
		anc[cur] = true
		cur = d.PPID
	}
	return out, anc
}
