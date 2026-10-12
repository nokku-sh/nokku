package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/nk/internal/state"
)

func TestManualNote(t *testing.T) {
	t.Parallel()

	stamp := time.Now().Add(-3*time.Hour - 12*time.Minute).UTC().Format(time.RFC3339)

	tests := []struct {
		name   string
		target state.Target
		ca     *state.CA
		want   string
	}{
		{
			name:   "a daemon target has no suffix",
			target: state.Target{DaemonID: "d-1", Metadata: map[string]string{"last_manual_sync": stamp}},
			want:   "",
		},
		{
			name: "a fresh stamp humanizes the sync age",
			target: state.Target{
				Metadata: map[string]string{"last_manual_sync": stamp},
			},
			want: "(manual, synced 3h12m ago)",
		},
		{
			name:   "a key rotated after the last sync needs a sync",
			target: state.Target{Metadata: map[string]string{"last_manual_sync": stamp}},
			ca:     &state.CA{RotatedAt: time.Now().Add(-time.Hour)},
			want:   "(manual, needs nk sync, its certificate authority was rotated)",
		},
		{
			name:   "a key older than the last sync is fine",
			target: state.Target{Metadata: map[string]string{"last_manual_sync": stamp}},
			ca:     &state.CA{RotatedAt: time.Now().Add(-24 * time.Hour)},
			want:   "(manual, synced 3h12m ago)",
		},
		{
			name: "an unparsable stamp reads as never synced",
			target: state.Target{
				Metadata: map[string]string{"last_manual_sync": "yesterday-ish"},
			},
			want: "(manual, never synced)",
		},
		{
			name:   "a missing stamp reads as never synced",
			target: state.Target{},
			want:   "(manual, never synced)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, manualNote(tt.target, tt.ca))
		})
	}
}
