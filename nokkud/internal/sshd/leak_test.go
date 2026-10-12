package sshd

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/nokkud/internal/leaktest"
)

func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}

func TestSessionChannelNoCommandDoesNotLeak(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	baseline := runtime.NumGoroutine()

	for i := range 50 {
		client, err := dial(t, addr, user, auth)
		must.NoError(err, "dial %d", i)
		sess, err := client.NewSession()
		if err != nil {
			client.Close()
		}
		must.NoError(err, "new session %d", i)
		sess.Close()
		client.Close()
	}

	// Let the server-side connection teardown settle before counting.
	is.Eventually(func() bool {
		return runtime.NumGoroutine() <= baseline+5
	}, 5*time.Second, 50*time.Millisecond)
	is.LessOrEqual(runtime.NumGoroutine(), baseline+5,
		"leaked session goroutines: baseline %d", baseline)

	client, err := dial(t, addr, user, auth)
	must.NoError(err, "post-leak dial")
	defer client.Close()
	sess, err := client.NewSession()
	must.NoError(err, "post-leak new session")
	defer sess.Close()
	out, err := sess.Output("echo ok")
	must.NoError(err, "post-leak exec")
	is.Equal("ok\n", string(out))
}
