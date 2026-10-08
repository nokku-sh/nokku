package db

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// A rotation drops old keys once it re-encrypted the columns it knows. An
// encrypted column missing from the list would lose its data.
func TestEncryptedColumnsMatchSqlc(t *testing.T) {
	raw, err := os.ReadFile("../../sqlc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	override := regexp.MustCompile(
		`- column: "([a-z_]+\.[a-z_]+)"\s+go_type:\s+import: "[^"]+"\s+type: "EncryptedBytes"`,
	)
	var want []string
	for _, m := range override.FindAllStringSubmatch(string(raw), -1) {
		want = append(want, m[1])
	}
	var got []string
	for _, c := range encryptedColumns {
		got = append(got, c.table+"."+c.column)
	}
	slices.Sort(want)
	slices.Sort(got)
	if len(want) == 0 || !slices.Equal(got, want) {
		t.Fatalf("encryptedColumns = %v, sqlc.yaml encrypts %v", got, want)
	}
}
