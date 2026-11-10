package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const targetID = "0199a0a0-0000-7000-8000-000000000003"

func TestFromAccess(t *testing.T) {
	t.Parallel()
	res := &nokkuv1.GetSubjectAccessResponse{
		Subject: &nokkuv1.GetSubjectAccessResponse_User{
			User: &nokkuv1.User{Id: new("u"), Name: new("alice")},
		},
		CertificateAuthority: &nokkuv1.CertificateAuthority{UserPublicKey: new("ssh-ed25519 AAAA")},
		Targets: []*nokkuv1.Target{
			{Id: new(targetID), Name: new("web")},
			{Id: new("../../etc"), Name: new("evil")},
			{Id: new("{" + targetID + "}"), Name: new("braces")},
		},
	}

	c := FromAccess(res)
	require.NotNil(t, c.User)
	assert.Equal(t, "alice", c.User.Name)
	require.NotNil(t, c.CA)
	assert.Equal(t, "ssh-ed25519 AAAA", c.CA.UserPublicKey)
	require.Len(t, c.Targets, 1, "non-canonical ids are dropped")
	assert.Equal(t, "web", c.Targets[0].Name)
}

// Names are printed by nk ls, nk doctor and in warnings.
func TestFromAccessDropsControlCharacters(t *testing.T) {
	t.Parallel()
	c := FromAccess(&nokkuv1.GetSubjectAccessResponse{
		Subject: &nokkuv1.GetSubjectAccessResponse_User{
			User: &nokkuv1.User{Id: new("u"), Name: new("al\x1b[2Jice"), Email: new("a@b.example\x07")},
		},
		Targets: []*nokkuv1.Target{{
			Id: new(targetID), Name: new("web\x1b]0;owned\x07"),
			Usernames: []string{"ro\x1bot", "alice"}, Endpoints: []string{"10.0.0.5\r\n"},
		}},
	})

	assert.Equal(t, &User{ID: "u", Name: "al[2Jice", Email: "a@b.example"}, c.User)
	require.Len(t, c.Targets, 1)
	assert.Equal(t, "web]0;owned", c.Targets[0].Name)
	assert.Equal(t, []string{"root", "alice"}, c.Targets[0].Usernames)
	assert.Equal(t, []string{"10.0.0.5"}, c.Targets[0].Endpoints)
}
