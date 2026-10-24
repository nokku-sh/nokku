package api

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeoutCapsAClientDeadline(t *testing.T) {
	// What connect builds from a Connect-Timeout-Ms header.
	ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
	defer cancel()

	var left time.Duration
	next := func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
		deadline, ok := ctx.Deadline()
		require.True(t, ok, "the handler ctx has no deadline")
		left = time.Until(deadline)
		return nil
	}
	err := newTimeoutInterceptor()(next)(ctx, connect.Spec{StreamType: connect.StreamTypeUnary}, nil)
	require.NoError(t, err)
	assert.LessOrEqual(t, left, 10*time.Second, "a client deadline lifted the cap")
}

func TestEndWithFollowsBothContexts(t *testing.T) {
	root, shutdown := context.WithCancel(t.Context())
	defer shutdown()

	ctx, release := endWith(t.Context(), root)
	defer release()
	require.NoError(t, ctx.Err())

	shutdown()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("the stream ctx outlived the root ctx")
	}
}
