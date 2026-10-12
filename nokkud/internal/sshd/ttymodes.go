package sshd

import (
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// RFC 4254 section 8 opcodes that map to one termios bit. Baud rates (128, 129) mean nothing on a pty.
type ttyFlag struct {
	field func(*unix.Termios) *uint32
	bit   uint32
}

var (
	iflag = func(t *unix.Termios) *uint32 { return &t.Iflag }
	oflag = func(t *unix.Termios) *uint32 { return &t.Oflag }
	cflag = func(t *unix.Termios) *uint32 { return &t.Cflag }
	lflag = func(t *unix.Termios) *uint32 { return &t.Lflag }
)

var ttyFlags = map[byte]ttyFlag{
	30: {iflag, unix.IGNPAR},
	31: {iflag, unix.PARMRK},
	32: {iflag, unix.INPCK},
	33: {iflag, unix.ISTRIP},
	34: {iflag, unix.INLCR},
	35: {iflag, unix.IGNCR},
	36: {iflag, unix.ICRNL},
	37: {iflag, unix.IUCLC},
	38: {iflag, unix.IXON},
	39: {iflag, unix.IXANY},
	40: {iflag, unix.IXOFF},
	41: {iflag, unix.IMAXBEL},
	42: {iflag, unix.IUTF8},
	50: {lflag, unix.ISIG},
	51: {lflag, unix.ICANON},
	52: {lflag, unix.XCASE},
	53: {lflag, unix.ECHO},
	54: {lflag, unix.ECHOE},
	55: {lflag, unix.ECHOK},
	56: {lflag, unix.ECHONL},
	57: {lflag, unix.NOFLSH},
	58: {lflag, unix.TOSTOP},
	59: {lflag, unix.IEXTEN},
	60: {lflag, unix.ECHOCTL},
	61: {lflag, unix.ECHOKE},
	62: {lflag, unix.PENDIN},
	70: {oflag, unix.OPOST},
	71: {oflag, unix.OLCUC},
	72: {oflag, unix.ONLCR},
	73: {oflag, unix.OCRNL},
	74: {oflag, unix.ONOCR},
	75: {oflag, unix.ONLRET},
	92: {cflag, unix.PARENB},
	93: {cflag, unix.PARODD},
}

// Control characters by opcode. VDSUSP, VFLUSH and VSTATUS do not exist on Linux.
var ttyChars = map[byte]int{
	1:  unix.VINTR,
	2:  unix.VQUIT,
	3:  unix.VERASE,
	4:  unix.VKILL,
	5:  unix.VEOF,
	6:  unix.VEOL,
	7:  unix.VEOL2,
	8:  unix.VSTART,
	9:  unix.VSTOP,
	10: unix.VSUSP,
	12: unix.VREPRINT,
	13: unix.VWERASE,
	14: unix.VLNEXT,
	16: unix.VSWTC,
	18: unix.VDISCARD,
}

func applyTTYModes(tty *os.File, modes []byte) error {
	if len(modes) == 0 {
		return nil
	}
	return ptyControl(tty, func(fd int) error {
		t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return err
		}
		parseTTYModes(t, modes)
		return unix.IoctlSetTermios(fd, unix.TCSETS, t)
	})
}

// Opcodes 1 to 159 carry a uint32. 0 ends the list, 160 and up are undefined and end it too, like sshd.
func parseTTYModes(t *unix.Termios, modes []byte) {
	for len(modes) >= 5 && modes[0] != 0 && modes[0] < 160 {
		op, arg := modes[0], binary.BigEndian.Uint32(modes[1:5])
		modes = modes[5:]
		if op == 90 || op == 91 {
			if arg != 0 {
				size := uint32(unix.CS7)
				if op == 91 {
					size = unix.CS8
				}
				t.Cflag = t.Cflag&^unix.CSIZE | size
			}
			continue
		}
		if f, ok := ttyFlags[op]; ok {
			if arg != 0 {
				*f.field(t) |= f.bit
			} else {
				*f.field(t) &^= f.bit
			}
			continue
		}
		if idx, ok := ttyChars[op]; ok {
			// 255 disables the character, like _POSIX_VDISABLE.
			if arg == 255 {
				arg = 0
			}
			t.Cc[idx] = uint8(min(arg, 255))
		}
	}
}
