package sshd

import (
	"os"
	"path/filepath"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

func TestEnvValueLastWins(t *testing.T) {
	t.Parallel()
	sess := &session{}
	sess.setEnv("LC_ALL", "first")
	sess.setEnv("TERM", "xterm")
	sess.setEnv("LC_ALL", "second")
	is := assert.New(t)

	v, ok := sess.envValue("LC_ALL")
	is.True(ok)
	is.Equal("second", v)

	v, ok = sess.envValue("TERM")
	is.True(ok)
	is.Equal("xterm", v)

	_, ok = sess.envValue("MISSING")
	is.False(ok)
}

func TestRecorderSessionIDFromKeyID(t *testing.T) {
	generated := uuid.NewV7().String()

	tests := []struct {
		name  string
		keyID string
		want  string
	}{
		{
			name:  "web session id is promoted",
			keyID: "nokku:web:session:01999650-9b7a-7d5e-9f2a-3f1e8f6f1a01",
			want:  "01999650-9b7a-7d5e-9f2a-3f1e8f6f1a01",
		},
		{
			name:  "direct login keeps the generated id",
			keyID: "nokku:login:user:alice",
			want:  generated,
		},
		{
			name:  "free-form value is refused",
			keyID: "nokku:web:session:other-session",
			want:  generated,
		},
		{
			name:  "uppercase is not canonical",
			keyID: "nokku:web:session:01999650-9B7A-7D5E-9F2A-3F1E8F6F1A01",
			want:  generated,
		},
		{
			name:  "wrong length is refused",
			keyID: "nokku:web:session:01999650-9b7a-7d5e-9f2a-3f1e8f6f1a0",
			want:  generated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
			require.NoError(t, os.MkdirAll(paths.RecordsDir(), 0o700))
			srv := &Server{}
			srv.access.Store(&access{policy: policy{Record: true}})
			sess := &session{
				server:    srv,
				sessionID: generated,
				conn: &ssh.ServerConn{Permissions: &ssh.Permissions{
					Extensions: map[string]string{"nokku-cert-key-id": tt.keyID},
				}},
				ctx:     t.Context(),
				sysUser: &account{Name: "tester"},
			}

			sess.startRecorder(80, 24)
			require.NotNil(t, sess.rec, "no recording started")
			sess.rec.Close()
			// The id names the file, and the recording in the core.
			assert.FileExists(t, filepath.Join(paths.RecordsDir(), tt.want+".cast.gz"))
		})
	}
}
