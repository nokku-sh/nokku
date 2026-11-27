package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
)

func TestListJSON(t *testing.T) {
	t.Parallel()
	s := &state.State{}
	s.Targets = []state.Target{
		{ID: "t-1", Name: "web", Usernames: []string{"root"}, Daemon: true},
		{ID: "t-2", Name: "bare"},
	}

	b, err := json.Marshal(listJSON(s))
	require.NoError(t, err)
	assert.JSONEq(t, `{"targets":[
		{"name":"web","host":"web.nk","users":["root"],"manual":false},
		{"name":"bare","users":[],"manual":true}
	]}`, string(b), "scripts get the ssh host and a list, never null")
}
