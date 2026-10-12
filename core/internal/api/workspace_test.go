package api

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/email"
)

// Refused before a workspace is made. The config has no database, getting that far would panic.
func TestCreateWorkspaceRefusesAnAddressOnCooldown(t *testing.T) {
	t.Setenv("NOKKU_SMTP_HOST", "")
	mail, err := email.New(t.Context(), "https://nokku.test")
	require.NoError(t, err)
	require.NoError(t, mail.SendOwnerLinkEmail(t.Context(), "ada@acme.test", "https://acme.nokku.test", "24h"))

	svc := &workspaceService{cfg: &config.Config{SaaS: true, Email: mail}}
	_, err = svc.CreateWorkspace(t.Context(), &nokkuv1.CreateWorkspaceRequest{
		Slug: new("acme"), Name: new("Acme"), OwnerEmail: new(" Ada@Acme.test"),
	})
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err), "got %v", err)
}
