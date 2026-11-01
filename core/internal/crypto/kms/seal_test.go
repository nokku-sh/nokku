package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/crypto"
)

// A ciphertext opens only in the row it was sealed for, anywhere else it fails.
func TestSealedSecretOpensOnlyInItsRow(t *testing.T) {
	keys, err := Ephemeral()
	require.NoError(t, err)

	row := crypto.AAD{Table: "audit_streams", Column: "secret", Workspace: "workspace-a", Row: "stream-1"}
	sealed, err := keys.Seal(row, []byte("siem token"))
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), "siem token")

	opened, err := keys.Open(row, sealed)
	require.NoError(t, err)
	assert.Equal(t, "siem token", string(opened))

	for name, elsewhere := range map[string]crypto.AAD{
		"another row":       {Table: row.Table, Column: row.Column, Workspace: row.Workspace, Row: "stream-2"},
		"another workspace": {Table: row.Table, Column: row.Column, Workspace: "workspace-b", Row: row.Row},
		"another column":    {Table: row.Table, Column: "url", Workspace: row.Workspace, Row: row.Row},
		"another table":     {Table: "recordings", Column: row.Column, Workspace: row.Workspace, Row: row.Row},
		// Without the lengths both would read "audit_streamssecret".
		"fields shifted": {Table: "audit_stream", Column: "ssecret", Workspace: row.Workspace, Row: row.Row},
	} {
		_, err := keys.Open(elsewhere, sealed)
		assert.Error(t, err, "%s opens the secret", name)
	}
}
