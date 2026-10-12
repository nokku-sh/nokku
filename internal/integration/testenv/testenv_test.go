//go:build integration

package testenv

import (
	"net"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// The first start is sent to a host port this test holds, which is what losing the pick looks like. Docker's
// own wording of that failure is what run looks for, so this fails when the wording changes.
func TestRunStartsAgainWhenTheHostPortIsTaken(t *testing.T) {
	held, err := net.Listen("tcp4", "0.0.0.0:0")
	require.NoError(t, err)
	defer held.Close()
	_, taken, err := net.SplitHostPort(held.Addr().String())
	require.NoError(t, err)

	// Options are applied once per start, a host config modifier more often than that.
	starts := 0
	clash := testcontainers.CustomizeRequestOption(func(req *testcontainers.GenericContainerRequest) error {
		if starts++; starts > 1 {
			return nil
		}
		return testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{network.MustParsePort("5432/tcp"): {{HostPort: taken}}}
		}).Customize(req)
	})
	c, err := run(t.Context(), postgresImage,
		testcontainers.WithEnv(map[string]string{"POSTGRES_PASSWORD": "postgres"}),
		testcontainers.WithExposedPorts("5432/tcp"),
		clash,
	)
	testcontainers.CleanupContainer(t, c, testcontainers.StopTimeout(0))
	require.NoError(t, err, "a taken host port ended the start")
	require.Equal(t, 2, starts)
}
