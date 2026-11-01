//go:build linux

package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	fanCloexec      = 0x1
	fanClassContent = 0x4
	fanMarkAdd      = 0x1
	fanModify       = 0x2
	fanOpenPerm     = 0x10000
	fanQOverflow    = 0x4000
	fanAllow        = 1
	fanDeny         = 2
	metaLen         = 24
)

func fanotifyInit(flags, eventFlags uint) (int, error) {
	fd, _, e := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, uintptr(flags), uintptr(eventFlags), 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func fanotifyMark(fd int, flags uint, mask uint64, path string) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(fd), uintptr(flags), uintptr(mask),
		dirfdCwd(), uintptr(unsafe.Pointer(p)), 0)
	if e != 0 {
		return e
	}
	return nil
}

func respond(fd, evfd int, allow bool) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:], uint32(evfd))
	r := uint32(fanAllow)
	if !allow {
		r = fanDeny
	}
	binary.LittleEndian.PutUint32(b[4:], r)
	syscall.Write(fd, b[:])
}

// Run watches the decoys until ctx ends. It needs root (CAP_SYS_ADMIN).
func Run(ctx context.Context, o Options) error {
	if o.Emit == nil {
		return errors.New("no alert emitter")
	}
	if !ValidContain(o.Contain) {
		return fmt.Errorf("unknown containment mode %q", o.Contain)
	}
	fd, err := fanotifyInit(fanClassContent|fanCloexec, uint(os.O_RDONLY|syscall.O_LARGEFILE))
	if err != nil {
		return fmt.Errorf("fanotify_init: %w (needs root)", err)
	}
	defer syscall.Close(fd)
	for _, p := range o.Paths {
		if err := fanotifyMark(fd, fanMarkAdd, fanOpenPerm|fanModify, p); err != nil {
			return fmt.Errorf("fanotify_mark %s: %w", p, err)
		}
	}
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	defer syscall.Close(ep)
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}
	if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, fd, &ev); err != nil {
		return err
	}
	self := os.Getpid()
	_, myAncestors := chain(self, 16)
	allow := map[string]bool{}
	for _, c := range o.AllowComm {
		allow[c] = true
	}
	buf := make([]byte, 64*1024)
	events := make([]syscall.EpollEvent, 1)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := syscall.EpollWait(ep, events, 300)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}
		rn, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return err
		}
		for off := 0; off+metaLen <= rn; {
			evLen := int(binary.LittleEndian.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > rn {
				break
			}
			mask := binary.LittleEndian.Uint64(buf[off+8:])
			evfd := int(int32(binary.LittleEndian.Uint32(buf[off+16:])))
			pid := int(int32(binary.LittleEndian.Uint32(buf[off+20:])))
			off += evLen
			handle(fd, evfd, pid, mask, self, myAncestors, allow, o)
		}
	}
}

func handle(fd, evfd, pid int, mask uint64, self int, ancestors map[int]bool, allow map[string]bool, o Options) {
	perm := mask&fanOpenPerm != 0
	if mask&fanQOverflow != 0 {
		o.Emit(Alert{Time: time.Now(), Event: "overflow", Action: "allowed", Note: "event queue overflowed; some touches were not reported"})
		return
	}
	path := ""
	if evfd >= 0 {
		path, _ = os.Readlink("/proc/self/fd/" + strconv.Itoa(evfd))
	}
	allowOpen := func() {
		if perm {
			respond(fd, evfd, true)
		}
		if evfd >= 0 {
			syscall.Close(evfd)
		}
	}
	if pid == self {
		allowOpen()
		return
	}
	// Collect everything about the process while the kernel still holds its open().
	p := describe(pid)
	ch, _ := chain(pid, 8)
	event := "access"
	switch {
	case perm:
		event = "open"
	case mask&fanModify != 0:
		event = "modify"
	}
	a := Alert{Time: time.Now().UTC(), Decoy: path, Event: event, PID: pid, PPID: p.PPID, UID: p.UID,
		Comm: p.Comm, Exe: p.Exe, Cmdline: p.Cmd, Chain: ch, Action: "allowed"}

	if allow[p.Comm] {
		allowOpen()
		return
	}
	protected := pid == 1 || ancestors[pid]
	deny := perm && !protected && o.Contain != ContainAlert
	if perm {
		respond(fd, evfd, !deny)
	}
	if evfd >= 0 {
		syscall.Close(evfd)
	}
	if deny {
		a.Action = "denied"
	}
	if !protected {
		switch o.Contain {
		case ContainSuspend:
			if err := syscall.Kill(pid, syscall.SIGSTOP); err == nil {
				a.Action = "suspended"
			}
		case ContainKill:
			if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
				a.Action = "killed"
			}
		}
	} else if o.Contain != ContainAlert {
		a.Note = "process is protected (init, or an ancestor of tracecheck): alert only"
	}
	o.Emit(a)
}

// dirfdCwd is AT_FDCWD (-100) as the unsigned word the syscall expects.
func dirfdCwd() uintptr {
	v := -100
	return uintptr(v)
}
