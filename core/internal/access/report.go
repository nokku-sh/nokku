package access

import (
	"bytes"
	"encoding/csv"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
)

// reportRow is one row of the report, and its shape in JSON.
type reportRow struct {
	Kind              string     `json:"kind"`
	SubjectID         string     `json:"subject_id"`
	Name              string     `json:"name"`
	Email             string     `json:"email,omitempty"`
	Active            bool       `json:"active"`
	Via               string     `json:"via,omitempty"`
	Target            string     `json:"target"`
	Account           string     `json:"account"`
	GrantedAt         time.Time  `json:"granted_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitzero"`
	LastCertificateAt *time.Time `json:"last_certificate_at,omitzero"`
	Stale             bool       `json:"stale"`
}

// Report renders who can log in where for an access review, in JSON or CSV.
func Report(rows []*db.ListAccessReportRow, format nokkuv1.ExportAuditLogsRequest_Format) ([]byte, error) {
	out := make([]reportRow, len(rows))
	for i, r := range rows {
		out[i] = reportRow{
			Kind:              r.Kind,
			SubjectID:         r.SubjectID,
			Name:              r.Name,
			Email:             r.Email,
			Active:            r.Active,
			Via:               r.Via,
			Target:            r.Target,
			Account:           r.Username,
			GrantedAt:         r.GrantedAt,
			ExpiresAt:         r.ExpiresAt,
			LastCertificateAt: r.LastCertAt,
			Stale:             r.Stale,
		}
	}

	//nolint:exhaustive // the request is validated, UNSPECIFIED never gets here
	switch format {
	case nokkuv1.ExportAuditLogsRequest_FORMAT_JSON:
		return json.Marshal(out)
	case nokkuv1.ExportAuditLogsRequest_FORMAT_CSV:
		return reportCSV(out)
	}
	return nil, fmt.Errorf("unsupported report format: %s", format)
}

func reportCSV(rows []reportRow) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"kind", "subject_id", "name", "email", "active", "via",
		"target", "account", "granted_at", "expires_at", "last_certificate_at", "stale",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.Kind, r.SubjectID, r.Name, r.Email, strconv.FormatBool(r.Active), r.Via,
			r.Target, r.Account, stamp(&r.GrantedAt), stamp(r.ExpiresAt), stamp(r.LastCertificateAt),
			strconv.FormatBool(r.Stale),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func stamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
