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
	"passkeys.data": "the public half of a passkey and its counters",
	"keysets.data":  "the keyset itself, wrapped by the KMS key or NOKKU_SECRET",
}

var (
	createTable = regexp.MustCompile(`^CREATE TABLE ([a-z_.]+) \(`)
	byteaColumn = regexp.MustCompile(`^\s+([a-z_]+) BYTEA\b`)
	sealedType  = regexp.MustCompile(`^\s+([a-z_]+) sealed\b`)
)

// A rotation drops old keys, so a column missing here would lose its data.
func TestSealedColumnsMatchSchema(t *testing.T) {
	schema, err := os.ReadFile("migrations/001_base.sql")
	require.NoError(t, err)
	want := columns(string(schema), sealedType)
	require.NotEmpty(t, want, "the schema has no sealed column")
	assert.ElementsMatch(t, want, sealed(), "sealedColumns and the sealed columns of the schema differ")
}

// A new BYTEA column is typed sealed, or named in clearBytea with a reason.
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

// unsealed lists BYTEA columns that clearBytea does not name.
func unsealed(schema string) []string {
	return slices.DeleteFunc(columns(schema, byteaColumn), func(column string) bool {
		_, ok := clearBytea[column]
		return ok
	})
}

// columns lists the table.column of every column line that matches.
func columns(schema string, column *regexp.Regexp) []string {
	var table string
	var out []string
	for line := range strings.Lines(schema) {
		if m := createTable.FindStringSubmatch(line); m != nil {
			table = m[1]
			continue
		}
		if m := column.FindStringSubmatch(line); m != nil {
			out = append(out, table+"."+m[1])
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
