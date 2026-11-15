// Package cgroup keeps the processes of SSH sessions in one cgroup per owner. Detaching never leaves a cgroup,
// so killing the group ends everything the owner started.
package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	mount = "/sys/fs/cgroup"
	// Inside the daemon's own cgroup, so it works under systemd, OpenRC and with no manager at all.
	treeName = "nokkud"
	// Only cgroup v2 on Linux 5.14 or newer has it.
	killFile = "cgroup.kill"
	// No owner starts with a dot, Start refuses those.
	probeGroup = ".probe"
)

// Tree holds one group per owner.
type Tree struct {
	dir string
}

// Open returns nil on a host that cannot keep sessions in cgroups, and logs which it is.
func Open(ctx context.Context) *Tree {
	var t *Tree
	own, err := ownGroup()
	if err == nil {
		t, err = openAt(ctx, filepath.Join(own, treeName))
	}
	if err != nil {
		slog.Info("sessions run without cgroups, a revoke leaves detached processes running", "reason", err)
		return nil
	}
	slog.Info("sessions run in cgroups, a revoke can end the processes they leave", "dir", t.dir)
	return t
}

// Start starts cmd in the owner's group. The process and all it forks stay there.
func (t *Tree) Start(cmd *exec.Cmd, owner string) error {
	// The name becomes a directory, it must not be able to point anywhere else.
	if owner == "" || strings.HasPrefix(owner, ".") || strings.ContainsAny(owner, "/\x00") {
		return fmt.Errorf("cgroup owner %q is no directory name", owner)
	}
	return t.start(cmd, owner)
}

// KillExcept ends every process in the groups of owners keep does not name, and returns those owners.
func (t *Tree) KillExcept(keep func(owner string) bool) (killed []string) {
	for _, owner := range t.groups() {
		if keep(owner) {
			continue
		}
		group := filepath.Join(t.dir, owner)
		// Only a group known to be empty is spared, a failed read must not save one.
		if alive, err := populated(group); err == nil && !alive {
			_ = os.Remove(group)
			continue
		}
		// #nosec G306 -- the kernel owns the file and its mode
		if err := os.WriteFile(filepath.Join(group, killFile), []byte("1"), 0o200); err != nil {
			slog.Error("kill cgroup failed", "owner", owner, "error", err)
			continue
		}
		killed = append(killed, owner)
	}
	return killed
}

// openAt proves the whole path once with a real process, so no session has to find out.
func openAt(ctx context.Context, dir string) (*Tree, error) {
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { // #nosec G301 -- kernel files
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, killFile)); err != nil {
		// On a cgroup v1 host Mkdir made a plain directory.
		_ = os.Remove(dir)
		return nil, fmt.Errorf("no cgroup v2 with %s: %w", killFile, err)
	}
	t := &Tree{dir: dir}
	if err := t.probe(ctx); err != nil {
		_ = os.Remove(filepath.Join(dir, probeGroup))
		_ = os.Remove(dir)
		return nil, fmt.Errorf("start a process in a cgroup: %w", err)
	}
	// No session runs yet, so no group that emptied can be in use.
	for _, name := range t.groups() {
		_ = os.Remove(filepath.Join(dir, name))
	}
	return t, nil
}

func (t *Tree) probe(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", ":")
	if err := t.start(cmd, probeGroup); err != nil {
		return err
	}
	return cmd.Wait()
}

func (t *Tree) start(cmd *exec.Cmd, name string) error {
	group := filepath.Join(t.dir, name)
	if err := os.Mkdir(group, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { // #nosec G301 -- kernel files
		return err
	}
	f, err := os.Open(group) // #nosec G304 -- Start checked the name
	if err != nil {
		return err
	}
	defer f.Close()
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, int(f.Fd())
	return cmd.Start()
}

func (t *Tree) groups() []string {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		slog.Error("read session cgroups failed", "error", err)
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// populated counts the whole subtree, so groups a root session nested in its own still show.
func populated(group string) (bool, error) {
	events, err := os.ReadFile(filepath.Join(group, "cgroup.events")) // #nosec G304 -- a path of the tree
	return bytes.Contains(events, []byte("populated 1")), err
}

// ownGroup reads the cgroup v2 line of /proc/self/cgroup, like 0::/system.slice/nokkud.service.
func ownGroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for line := range strings.Lines(string(data)) {
		path, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok {
			continue
		}
		// A cgroup namespace shows a group outside its root as /../name.
		if rel := strings.TrimPrefix(path, "/"); rel != "" && !filepath.IsLocal(rel) {
			return "", fmt.Errorf("own cgroup %q is outside the mounted tree", path)
		}
		return filepath.Join(mount, path), nil
	}
	return "", errors.New("no cgroup v2 on this host")
}
