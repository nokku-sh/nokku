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
