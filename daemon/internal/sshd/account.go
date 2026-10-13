package sshd

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Matching OpenSSH, only root may log in while this file exists.
const nologinPath = "/etc/nologin"

type account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
	// Zero means the account never expires.
	Expires time.Time
}

// Root is never blocked by nologin, so an operator can still get in to fix the machine.
func loginAllowed(a *account, nologinPath string) error {
	if !a.Expires.IsZero() && !time.Now().Before(a.Expires) {
		return fmt.Errorf("account %s expired on %s", a.Name, a.Expires.Format(time.DateOnly))
	}
	if a.UID == 0 {
		return nil
	}
	msg, err := os.ReadFile(nologinPath)
	if err != nil {
		return nil
	}
	if len(bytes.TrimSpace(msg)) == 0 {
		return errors.New("logins are disabled by /etc/nologin")
	}
	return fmt.Errorf("logins are disabled: %s", strings.TrimSpace(string(msg)))
}

// getent resolves NSS and LDAP users too, a static binary cannot see those on its own.
func lookupAccount(name string) (*account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 - name passed the principals lookup, which only holds valid usernames.
	out, err := exec.CommandContext(ctx, "getent", "passwd", name).Output()
	if err != nil {
		return nil, fmt.Errorf("user %q not found", name)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	// getent takes a number as a uid. The entry has to be the name asked for.
	if len(parts) != 7 || parts[0] != name {
		return nil, fmt.Errorf("user %q not found", name)
	}
	uid, uidErr := strconv.ParseUint(parts[2], 10, 32)
	gid, gidErr := strconv.ParseUint(parts[3], 10, 32)
	if uidErr != nil || gidErr != nil {
		return nil, fmt.Errorf("user %q has a bad passwd entry", name)
	}
	return &account{
		Name: name,
		UID:  uint32(uid),
		GID:  uint32(gid),
		Home: parts[5],
		// A lock shell (nologin, false) is used as is and fails the session. Only an empty field means /bin/sh.
		Shell:   cmp.Or(parts[6], "/bin/sh"),
		Expires: shadowExpiry(ctx, name),
	}, nil
}

// The expiry day set by chage -E. OpenSSH denies it through pam_unix, so the daemon does too. No entry means none.
func shadowExpiry(ctx context.Context, name string) time.Time {
	out, err := exec.CommandContext(ctx, "getent", "shadow", name).Output() // #nosec G204
	if err != nil {
		return time.Time{}
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(parts) != 9 || parts[0] != name {
		return time.Time{}
	}
	days, err := strconv.ParseInt(parts[7], 10, 64)
	if err != nil || days < 0 {
		return time.Time{}
	}
	return time.Unix(days*24*60*60, 0)
}

func groupIDs(a *account) ([]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "id", "-G", a.Name).Output() // #nosec G204
	if err != nil {
		return nil, fmt.Errorf("lookup groups for %s: %w", a.Name, err)
	}
	var ids []uint32
	for g := range strings.FieldsSeq(string(out)) {
		id, parseErr := strconv.ParseUint(g, 10, 32)
		if parseErr != nil {
			return nil, fmt.Errorf("lookup groups for %s: %w", a.Name, parseErr)
		}
		ids = append(ids, uint32(id))
	}
	return ids, nil
}

func cmdEnv(a *account) []string {
	env := []string{
		"HOME=" + a.Home,
		"USER=" + a.Name,
		"LOGNAME=" + a.Name,
		"SHELL=" + a.Shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}
	// Only harmless locale variables are inherited, so the admin's agent socket cannot leak.
	for _, key := range []string{"LANG", "LC_ALL", "LC_CTYPE", "TZ", "MAIL"} {
		if val, exists := os.LookupEnv(key); exists {
			env = append(env, key+"="+val)
		}
	}
	return env
}

func sysProcAttr(a *account) (*syscall.SysProcAttr, error) {
	attr := &syscall.SysProcAttr{Setsid: true}

	// Non-root gets EPERM from setgroups(2) even for its own groups, so Credential would fail every exec.
	if os.Geteuid() != 0 {
		return attr, nil
	}
	groups, err := groupIDs(a)
	if err != nil {
		return nil, err
	}
	attr.Credential = &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: groups}
	return attr, nil
}
