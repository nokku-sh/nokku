//go:build integration

package api_test

import (
	"strings"
	"testing"
	"uuid"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/audit"
)

// A UUID in capitals passes validation and Postgres finds the row, but it hands the id back in small letters. A
// secret sealed with the capital one would never open again, and rotate-secrets would fail for every workspace.
func TestASecretSealedThroughACapitalIDStillOpens(t *testing.T) {
	cfg, srv := enterprise(t)
	owner := header(
		"Authorization",
		"Bearer "+seedMember(t, cfg, seedWorkspace(t, cfg), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER),
	)
	streams := nokkuv1connect.NewAuditStreamServiceClient(
		connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL), owner),
	)
	created, err := streams.CreateAuditStream(t.Context(), &nokkuv1.CreateAuditStreamRequest{
		Kind:   nokkuv1.AuditStreamKind_AUDIT_STREAM_KIND_SPLUNK.Enum(),
		Url:    new("https://splunk.example.com/services/collector/event"),
		Secret: new("hec-token-1"),
	})
	require.NoError(t, err)
	id := created.GetStream().GetId()

	_, err = streams.UpdateAuditStream(t.Context(),
		masked(&nokkuv1.UpdateAuditStreamRequest{Id: new(strings.ToUpper(id)), Secret: new("hec-token-2")}))
	require.NoError(t, err)

	row, err := cfg.Conn.Sys().GetAuditStream(t.Context(), id)
	require.NoError(t, err)
	secret, err := cfg.Keyset.Open(audit.SecretAAD(row.WorkspaceID, row.ID), row.Secret)
	require.NoError(t, err, "the secret does not open with the id as the database spells it")
	assert.Equal(t, "hec-token-2", string(secret))
}

// A daemon names its recording. Only the spelling the database gives back can be sealed into its key.
func TestUploadRefusesARecordingIDInCapitals(t *testing.T) {
	cfg, srv := newTestAPI(t)
	key, enrolled := enrollTestDaemon(t, cfg, srv, seedWorkspace(t, cfg), true)
	id := uuid.NewV7().String()

	stream := openUpload(t.Context(), t, cfg, srv, key, enrolled.GetAccessToken(), strings.ToUpper(id))
	_, err := stream.CloseAndReceive()
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)

	_, err = cfg.Conn.Sys().GetRecording(t.Context(), id)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "a refused upload left a row behind")
}
