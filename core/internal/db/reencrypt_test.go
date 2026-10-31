package db

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearBytea are the BYTEA columns that hold no secret, and why.
var clearBytea = map[string]string{
	"user_avatars.image": "a picture the workspace sees anyway",
	"credentials.data":   "the public half of a passkey and its counters",
	"keysets.data":       "the keyset itself, wrapped by the KMS key or NOKKU_SECRET",
}

var (
	createTable = regexp.MustCompile(`^CREATE TABLE ([a-z_.]+) \(`)
	byteaColumn = regexp.MustCompile(`^\s+([a-z_]+) BYTEA\b`)
)

// A rotation drops old keys, so a sealed column missing from the list would lose its data.
func TestSealedColumnsMatchSqlc(t *testing.T) {
	raw, err := os.ReadFile("../../sqlc.yaml")
	require.NoError(t, err)
	override := regexp.MustCompile(
		`- column: "([a-z_]+\.[a-z_]+)"\s+go_type:\s+import: "[^"]+"\s+type: "Sealed"`,
	)
	var want []string
	for _, m := range override.FindAllStringSubmatch(string(raw), -1) {
		want = append(want, m[1])
	}
	require.NotEmpty(t, want, "sqlc.yaml maps no column to crypto.Sealed")
	assert.ElementsMatch(t, want, sealed(), "sealedColumns and the Sealed overrides of sqlc.yaml differ")
}

// A secret stored in the clear fails here. A new BYTEA column is sealed, or named in clearBytea with a reason.
func TestEveryByteaColumnIsSealed(t *testing.T) {
	schema, err := os.ReadFile("migrations/001_base.sql")
	require.NoError(t, err)
	assert.Empty(t, unsealed(string(schema)), "BYTEA columns that are neither sealed nor in clearBytea")
}

func TestUnsealedFindsAPlantedColumn(t *testing.T) {
	schema, err := os.ReadFile("migrations/001_base.sql")
	require.NoError(t, err)
	planted := string(schema) + "\nCREATE TABLE webhooks (\n  id UUID PRIMARY KEY,\n  token BYTEA NOT NULL\n);\n"
	assert.Equal(t, []string{"webhooks.token"}, unsealed(planted))
}

// unsealed lists the BYTEA columns of schema that are neither in sealedColumns nor in clearBytea.
func unsealed(schema string) []string {
	var table string
	var out []string
	for line := range strings.Lines(schema) {
		if m := createTable.FindStringSubmatch(line); m != nil {
			table = m[1]
			continue
		}
		m := byteaColumn.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		column := table + "." + m[1]
		if _, ok := clearBytea[column]; !ok && !slices.Contains(sealed(), column) {
			out = append(out, column)
		}
	}
	return out
}

func sealed() []string {
	var out []string
	for _, c := range sealedColumns {
		out = append(out, c.table+"."+c.column)
	}
	return out
}
