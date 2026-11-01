package access

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

func TestReportCSV(t *testing.T) {
	granted := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	rows := []*db.ListAccessReportRow{
		{
			Kind: "user", SubjectID: "u1", Name: "Ada", Email: "ada@x", Active: true, Via: "ops", Target: "web-1",
			Username: "deploy", GrantedAt: granted, Enforced: true, Stale: true,
		},
		{
			Kind: "service_account", SubjectID: "s1", Name: "ci", Active: true, Target: "web-1", Username: "deploy",
			GrantedAt: granted, LastCertAt: new(granted.Add(time.Hour)), ExpiresAt: new(granted.Add(48 * time.Hour)),
		},
	}

	data, err := Report(rows, nokkuv1.ExportAuditLogsRequest_FORMAT_CSV)
	require.NoError(t, err)
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 3, "a header and one line per row")
	assert.Equal(t, []string{
		"user", "u1", "Ada", "ada@x", "true", "ops", "web-1", "deploy",
		"2026-01-02T03:04:05Z", "", "", "true", "true",
	}, records[1], "a stale grant through a team")
	assert.Equal(t, "false", records[2][11], "a grant that lets nobody in today is marked")
	assert.Equal(t, "2026-01-04T03:04:05Z", records[2][9], "the end of a grant that ends")
	assert.Equal(t, "2026-01-02T04:04:05Z", records[2][10], "the last certificate")
}

func TestReportJSONLeavesOutWhatIsUnset(t *testing.T) {
	rows := []*db.ListAccessReportRow{{Kind: "user", Name: "Ada", Target: "web-1", Username: "deploy"}}

	data, err := Report(rows, nokkuv1.ExportAuditLogsRequest_FORMAT_JSON)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "expires_at", "a grant for good has no end")
	assert.NotContains(t, string(data), "last_certificate_at", "no certificate yet")
	assert.Contains(t, string(data), `"account":"deploy"`)
}

// These values come from people and SCIM, a spreadsheet must not run them.
func TestReportCSVStopsFormulas(t *testing.T) {
	rows := []*db.ListAccessReportRow{{
		Kind: "user", SubjectID: "u1", Name: "=1+1", Email: "+a@x", Active: true, Via: "-ops", Target: "@web",
		Username: "=root",
	}}

	data, err := Report(rows, nokkuv1.ExportAuditLogsRequest_FORMAT_CSV)
	require.NoError(t, err)
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	r := records[1]
	assert.Equal(t, []string{"'=1+1", "'+a@x", "'-ops", "'@web", "'=root"}, []string{r[2], r[3], r[5], r[6], r[7]})
}
