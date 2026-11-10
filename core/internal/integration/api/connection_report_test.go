//go:build integration

package api_test

import (
	"encoding/json/v2"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	nklogin "github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// A daemon reports who logged in. Both ends of a connection land in the audit log, written by the daemon and about
// the person. A report that comes twice is stored once, and a flood from one daemon is held back.
func TestConnectionReport(t *testing.T) {
	cfg, srv := newTestAPI(t)
	ws := testWorkspace.ID
	key, enrolled := enrollTestDaemon(t, cfg, srv, ws, true)
	person := seedUser(t, cfg, ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	principal := nklogin.Principal(person.ID, enrolled.GetTargetId(), "deploy")

	// A stream takes its headers from the context, the client's interceptors only see unary calls.
	ctx, call := connect.NewClientContext(t.Context())
	call.RequestHeader().Set("Authorization", "DPoP "+enrolled.GetAccessToken())
	call.RequestHeader().Set("DPoP", dpopProof(t, cfg, key,
		nokkuv1connect.DaemonControlServiceConnectProcedure, enrolled.GetAccessToken()))
	stream, err := nokkuv1connect.NewDaemonControlServiceClient(clientOn(srv)).Connect(ctx)
	require.NoError(t, err)
	acks := make(chan struct{}, 8)
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				return
			}
			if msg.GetConnectionReportAck() != nil {
				acks <- struct{}{}
			}
		}
	}()
	acked := func(within time.Duration) bool {
		select {
		case <-acks:
			return true
		case <-time.After(within):
			return false
		}
	}
	send := func(events ...*nokkuv1.ConnectionEvent) {
		t.Helper()
		require.NoError(t, stream.Send(&nokkuv1.ConnectRequest{Msg: &nokkuv1.ConnectRequest_ConnectionReport{
			ConnectionReport: &nokkuv1.ConnectionReport{Events: events},
		}}))
	}
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	event := func(id string, closed bool) *nokkuv1.ConnectionEvent {
		return &nokkuv1.ConnectionEvent{
			ConnectionId: &id, Closed: &closed, Time: timestamppb.New(at), Principal: &principal,
			KeyId: new("key-1"), RemoteAddr: new("203.0.113.9:5022"), ClientVersion: new("SSH-2.0-OpenSSH_10.0"),
		}
	}
	about := func(target string) []*db.ListAuditLogsRow {
		var rows []*db.ListAuditLogsRow
		inWorkspace(t, cfg, ws, func(q *db.Queries) (err error) {
			rows, err = q.ListAuditLogs(t.Context(), &db.ListAuditLogsParams{Target: &target, Limit: 500})
			return err
		})
		return rows
	}

	connection := uuid.NewV7().String()
	report := []*nokkuv1.ConnectionEvent{event(connection, false), event(connection, true)}
	send(report...)
	require.True(t, acked(5*time.Second), "the core did not ack the report")
	// As if the ack was lost: the daemon sends the same report again.
	send(report...)
	require.True(t, acked(5*time.Second), "the core did not ack the report it had already")

	rows := about(person.ID)
	require.Len(t, rows, 2, "a report that came twice must be stored once")
	// Newest first, and the close was written after the open.
	closed, opened := rows[0], rows[1]
	assert.Equal(t, "ConnectionClose", closed.Action)
	assert.Equal(t, "ConnectionOpen", opened.Action)
	assert.Equal(t, enrolled.GetId(), opened.ActorID, "the daemon is the one who says so")
	assert.Equal(t, "daemon", opened.ActorKind)
	assert.NotEmpty(t, opened.ActorName, "the daemon goes by its server's name")
	var details struct {
		Username string    `json:"username"`
		Subject  string    `json:"subject"`
		Target   string    `json:"target"`
		KeyID    string    `json:"key_id"`
		Remote   string    `json:"remote"`
		At       time.Time `json:"at"`
	}
	require.NoError(t, json.Unmarshal(opened.Details, &details))
	assert.Equal(t, "deploy", details.Username)
	assert.Equal(t, person.Name, details.Subject, "the person is named as the core knows them")
	assert.Equal(t, opened.ActorName, details.Target)
	assert.Equal(t, "key-1", details.KeyID)
	assert.Equal(t, "203.0.113.9:5022", details.Remote)
	assert.True(t, at.Equal(details.At), "the daemon's time is kept next to the core's")
	assert.WithinDuration(t, time.Now(), opened.Timestamp, time.Minute, "the row's own time is the core's")

	// A principal the core never signed is kept as sent, about nobody.
	forged := event(uuid.NewV7().String(), false)
	forged.Principal = new("root")
	send(forged)
	require.True(t, acked(5*time.Second))
	assert.Len(t, about(person.ID), 2)

	// The burst is 200 events. What comes after waits for its ack, at 20 events a second.
	flood := func() []*nokkuv1.ConnectionEvent {
		events := make([]*nokkuv1.ConnectionEvent, 100)
		for i := range events {
			events[i] = event(uuid.NewV7().String(), false)
		}
		return events
	}
	send(flood()...)
	require.True(t, acked(5*time.Second))
	send(flood()...)
	send(flood()...)
	acked(5 * time.Second)
	assert.False(t, acked(time.Second), "a flood from one daemon went straight into the audit log")
	assert.Less(t, len(about(person.ID)), 2+300)
}
