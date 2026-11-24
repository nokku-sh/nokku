package api

import (
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// Only nk and a service account report a host.
func TestABrowserReportsNoHost(t *testing.T) {
	t.Parallel()
	ctx := actor.ContextWithPrincipal(t.Context(), actor.Principal{ID: "u1", Kind: actor.KindUser})
	_, err := (&targetService{}).SyncTargetUsers(ctx, &nokkuv1.SyncTargetUsersRequest{})
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "a browser session sent a sync")
}

// A pin from an older nk keeps the key's comment, the same key without it is no new key.
func TestRepinIgnoresTheComment(t *testing.T) {
	t.Parallel()
	added, other := "a", "b"
	target := &db.Target{HostPublicKey: new("ssh-ed25519 AAAAkey root@host"), CreatedBy: &added}
	sync := func(key string) *nokkuv1.SyncTargetUsersRequest {
		return &nokkuv1.SyncTargetUsersRequest{HostPublicKey: &key}
	}
	someone := actor.Principal{ID: other}

	require.NoError(t, repinTarget(someone, target, sync("ssh-ed25519 AAAAkey")), "the comment made a new key")
	require.Error(t, repinTarget(someone, target, sync("ssh-ed25519 AAAAother")), "someone else pinned a new key")
	require.NoError(t, repinTarget(actor.Principal{ID: added}, target, sync("ssh-ed25519 AAAAother")))
}
