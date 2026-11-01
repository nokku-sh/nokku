package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeTimestamp(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	assert.Nil(t, SafeTimestamp(nil))

	got := SafeTimestamp(&now)
	require.NotNil(t, got)
	assert.WithinDuration(t, now, got.AsTime(), 0)
}
