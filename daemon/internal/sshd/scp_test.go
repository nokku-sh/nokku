package sshd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerSCPLegacy(t *testing.T) {
	if !isTestBinary() {
		t.Skip("legacy scp test requires the test binary on PATH")
	}
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skip("scp not installed")
	}

	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	must := require.New(t)
	user := currentUser(t)
	home := currentHome(t)
	_, port := hostPort(t, addr)
	scratches := filepath.Join(home, "nokkud-scp-scratch")
	must.NoError(os.RemoveAll(scratches))
	defer os.RemoveAll(scratches)
	must.NoError(os.MkdirAll(scratches, 0o755))

	src := filepath.Join(scratches, "src.txt")
	must.NoError(os.WriteFile(src, []byte("legacy scp payload\n"), 0o644))

	identity := userCertFile(t, ca)
	opts := []string{
		"-O",
		"-q",
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(scratches, "known_hosts"),
		"-P", port,
	}
	remote := func(p string) string {
		return fmt.Sprintf("%s@127.0.0.1:%s", user, p)
	}

	tests := []struct {
		name      string
		extraOpts []string
		args      []string
		setup     func(t *testing.T)
		verify    string
		want      string
	}{
		{
			name:   "up",
			args:   []string{src, remote(filepath.Join(scratches, "up.txt"))},
			verify: filepath.Join(scratches, "up.txt"),
			want:   "legacy scp payload\n",
		},
		{
			name:   "down",
			args:   []string{remote(src), filepath.Join(scratches, "dst.txt")},
			verify: filepath.Join(scratches, "dst.txt"),
			want:   "legacy scp payload\n",
		},
		{
			// The destination must exist for scp to keep the source directory name.
			name:      "recursive up",
			extraOpts: []string{"-r"},
			setup: func(t *testing.T) {
				setup := require.New(t)
				srcdir := filepath.Join(scratches, "srcdir")
				setup.NoError(os.MkdirAll(filepath.Join(srcdir, "sub"), 0o755))
				setup.NoError(os.WriteFile(
					filepath.Join(srcdir, "sub", "f.txt"),
					[]byte("nested\n"),
					0o644,
				))
				setup.NoError(os.Mkdir(filepath.Join(scratches, "uptree"), 0o755))
			},
			args:   []string{filepath.Join(scratches, "srcdir"), remote(filepath.Join(scratches, "uptree"))},
			verify: filepath.Join(scratches, "uptree", "srcdir", "sub", "f.txt"),
			want:   "nested\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}
			runLegacySCP(t, opts, tt.extraOpts, tt.args, tt.verify, tt.want)
		})
	}
}

func runLegacySCP(t *testing.T, opts, extraOpts, args []string, verify, want string) {
	t.Helper()
	is := assert.New(t)
	must := require.New(t)
	all := append(slices.Clone(opts), extraOpts...)
	all = append(all, args...)
	cmd := exec.Command("scp", all...)
	out, err := cmd.CombinedOutput()
	must.NoError(err, "scp: %s", out)
	b, err := os.ReadFile(verify)
	must.NoError(err)
	is.Equal(want, string(b))
}
