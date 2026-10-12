package sshd

import (
	"math"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Every ioctl on the master goes through ptyControl, so it stays non-blocking and a close interrupts a read.
func openPTY() (ptmx, tty *os.File, err error) {
	if ptmx, err = os.OpenFile("/dev/ptmx", os.O_RDWR, 0); err != nil {
		return nil, nil, err
	}
	var n uint32
	err = ptyControl(ptmx, func(fd int) (err error) {
		if n, err = unix.IoctlGetUint32(fd, unix.TIOCGPTN); err != nil {
			return err
		}
		return unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)
	})
	if err == nil {
		tty, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	}
	if err != nil {
		_ = ptmx.Close()
		return nil, nil, err
	}
	return ptmx, tty, nil
}

// Unlike Fd, this does not put f in blocking mode.
func ptyControl(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	if cerr := rc.Control(func(fd uintptr) { err = fn(int(fd)) }); cerr != nil {
		return cerr
	}
	return err
}

func setWinsize(ptmx *os.File, cols, rows uint32) error {
	return ptyControl(ptmx, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{
			Col: uint16(min(cols, math.MaxUint16)),
			Row: uint16(min(rows, math.MaxUint16)),
		})
	})
}

// Password prompts turn echo off. Fails closed so secrets cannot leak.
func echoEnabled(ptmx *os.File) bool {
	echo := false
	_ = ptyControl(ptmx, func(fd int) error {
		termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		echo = err == nil && termios.Lflag&unix.ECHO != 0
		return err
	})
	return echo
}
