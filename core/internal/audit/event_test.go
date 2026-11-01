package audit

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Clients pick these values, and an admin opens the export in a spreadsheet.
func TestExportDoesNotRunFormulas(t *testing.T) {
	out, err := eventsCSV([]*Event{{
		Timestamp: time.Now(),
		ActorName: "=HYPERLINK(\"https://evil.example\")",
		Target:    "+1+1",
		IP:        "192.0.2.7",
		UserAgent: "@SUM(1)",
	}})
	require.NoError(t, err)
	rows, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	row := rows[1]
	assert.Equal(t, "'=HYPERLINK(\"https://evil.example\")", row[5])
	assert.Equal(t, "'+1+1", row[7])
	assert.Equal(t, "192.0.2.7", row[9], "a plain value stays as it is")
	assert.Equal(t, "'@SUM(1)", row[10])
}
