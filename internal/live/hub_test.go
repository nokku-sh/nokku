package live

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"
)

func TestABurstIsOneChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := New()
		s := h.Subscribe("ws")
		defer s.Close()

		h.Changed("ws", "daemons")
		h.Changed("ws", "daemons")
		// Lands while the stream waits for the burst to settle.
		go func() {
			time.Sleep(settle / 2)
			h.Changed("ws", "recordings")
		}()

		start := time.Now()
		c, err := s.Next(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []string{
			nokkuv1connect.DaemonServiceName,
			nokkuv1connect.DashboardServiceName,
			nokkuv1connect.RecordingServiceName,
			nokkuv1connect.TargetServiceName,
		}, c.Services)
		assert.False(t, c.Everything)
		assert.Less(t, time.Since(start), time.Second, "a lone change is heard right away")

		start = time.Now()
		c, err = s.Next(t.Context())
		require.NoError(t, err)
		assert.Equal(t, Change{}, c, "nothing is told twice")
		assert.Equal(t, idle, time.Since(start))
	})
}

func TestAnUnmappedTableMeansEverything(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := New()
		s := h.Subscribe("ws")
		defer s.Close()

		h.Changed("ws", "daemons")
		h.Changed("ws", "teams")

		c, err := s.Next(t.Context())
		require.NoError(t, err)
		assert.Equal(t, Change{Everything: true}, c)
	})
}

func TestAWorkspaceHearsOnlyItself(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := New()
		s := h.Subscribe("ws")
		defer s.Close()

		h.Changed("other", "teams")

		c, err := s.Next(t.Context())
		require.NoError(t, err)
		assert.Equal(t, Change{}, c)
	})
}

func TestABusyWorkspaceIsPaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := New()
		s := h.Subscribe("ws")
		defer s.Close()

		h.Changed("ws", "daemons")
		_, err := s.Next(t.Context())
		require.NoError(t, err)
		first := time.Now()

		h.Changed("ws", "daemons")
		c, err := s.Next(t.Context())
		require.NoError(t, err)
		assert.NotEmpty(t, c.Services)
		assert.GreaterOrEqual(t, time.Since(first), minGap)
	})
}

func TestAClosedStreamIsForgotten(t *testing.T) {
	h := New()
	s := h.Subscribe("ws")
	s.Close()
	assert.Empty(t, h.subs)
	h.Changed("ws", "teams")
}
