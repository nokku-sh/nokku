package api

import (
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestKeyTTL(t *testing.T) {
	t.Parallel()
	refused := func(ts *timestamppb.Timestamp, why string) {
		t.Helper()
		_, err := keyTTL(ts)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), why)
	}
	refused(nil, "a key without an end date")
	refused(timestamppb.New(time.Now().Add(-time.Minute)), "an end date in the past")
	refused(timestamppb.New(time.Now().Add(400*24*time.Hour)), "a key for longer than a year")

	ttl, err := keyTTL(timestamppb.New(time.Now().Add(365 * 24 * time.Hour)))
	require.NoError(t, err, "the one year preset")
	assert.Greater(t, ttl, 364*24*time.Hour)
}
