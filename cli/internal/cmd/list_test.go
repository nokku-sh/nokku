package cmd

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
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
			name:   "a sync during a rollover left the retired key on the host",
			target: state.Target{Metadata: map[string]string{"last_manual_sync": stamp}},
			ca: &state.CA{
				RotatedAt:            time.Now().Add(-24 * time.Hour),
				PreviousTrustedUntil: time.Now().Add(-time.Hour),
			},
			want: "(manual, needs nk sync, it still trusts a retired certificate authority key)",
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

func TestListJSON(t *testing.T) {
	t.Parallel()
	s := &state.State{}
	s.Targets = []state.Target{
		{ID: "t-1", Name: "web", Usernames: []string{"root"}, DaemonID: "d"},
		{ID: "t-2", Name: "bare"},
	}

	b, err := json.Marshal(listJSON(s, map[string]string{"t-1": "nokku/web"}))
	require.NoError(t, err)
	assert.JSONEq(t, `{"targets":[
		{"name":"web","host":"nokku/web","users":["root"],"manual":false},
		{"name":"bare","users":[],"manual":true}
	]}`, string(b), "scripts get the ssh host and a list, never null")
}
