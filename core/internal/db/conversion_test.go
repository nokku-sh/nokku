package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A user SCIM linked to but did not create keeps their own address.
func TestUserScimManagedIsTheColumn(t *testing.T) {
	t.Parallel()
	adopted := &User{ScimExternalID: new("ext-1")}
	assert.False(t, adopted.ToProto().GetScimManaged())

	created := &User{ScimExternalID: new("ext-2"), ScimManaged: true}
	assert.True(t, created.ToProto().GetScimManaged())
}
