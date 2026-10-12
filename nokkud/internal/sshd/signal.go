package sshd

import (
	"os"
	"syscall"
)

// RFC 4254 signal names.
var sshSignals = map[string]os.Signal{
	"ABRT": syscall.SIGABRT,
	"ALRM": syscall.SIGALRM,
	"FPE":  syscall.SIGFPE,
	"HUP":  syscall.SIGHUP,
	"ILL":  syscall.SIGILL,
	"INT":  syscall.SIGINT,
	"KILL": syscall.SIGKILL,
	"PIPE": syscall.SIGPIPE,
	"QUIT": syscall.SIGQUIT,
	"SEGV": syscall.SIGSEGV,
	"TERM": syscall.SIGTERM,
	"USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

func signalByName(name string) (os.Signal, bool) {
	sig, ok := sshSignals[name]
	return sig, ok
}

// code is the shell exit code (128+n). ok is false on a normal exit, where the caller sends exit-status.
func processSignal(st *os.ProcessState) (name string, code int, ok bool) {
	if st == nil {
		return "", 0, false
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return "", 0, false
	}
	sig := ws.Signal()
	code = 128 + int(sig)
	for n, s := range sshSignals {
		if s == sig {
			return n, code, true
		}
	}
	return "", code, true
}
