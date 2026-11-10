package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func event(id string) Event {
	return Event{ConnectionID: id, Time: time.Now().Truncate(time.Second), Principal: "p"}
}

// What the core has not acked is still there after a restart, in order.
func TestSpoolOutlivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports")
	s := Open(path)
	for _, id := range []string{"a", "b", "c"} {
		s.Add(event(id))
	}
	select {
	case <-s.Ready():
	default:
		t.Fatal("an added event did not wake the sender")
	}
	sent, _ := s.Next()
	require.Len(t, sent, 3)
	again, _ := s.Next()
	assert.Equal(t, sent, again, "events must stay until the core acked them")

	s.Done(2, 0)
	s.Add(event("d"))

	restarted := Open(path)
	left, _ := restarted.Next()
	require.Len(t, left, 2)
	assert.Equal(t, "c", left[0].ConnectionID)
	assert.Equal(t, "d", left[1].ConnectionID)
	assert.True(t, sent[2].Time.Equal(left[0].Time))

	restarted.Done(2, 0)
	left, _ = Open(path).Next()
	assert.Empty(t, left, "acked events came back after a restart")
}

// A core that stays away must not fill the disk. What does not fit is counted, and the count goes with a report.
func TestSpoolDropsWhenFull(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "reports"))
	for range maxEvents + 3 {
		s.Add(event("x"))
	}
	events, dropped := s.Next()
	assert.Len(t, events, Batch, "one report carries one batch")
	assert.EqualValues(t, 3, dropped)

	s.Done(len(events), dropped)
	_, dropped = s.Next()
	assert.Zero(t, dropped, "a drop was reported twice")
	s.Add(event("y"))
	_, dropped = s.Next()
	assert.Zero(t, dropped, "there is room again")
}
