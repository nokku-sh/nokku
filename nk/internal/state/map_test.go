package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const (
	caID     = "0199a0a0-0000-7000-8000-000000000002"
	targetID = "0199a0a0-0000-7000-8000-000000000003"
)

func TestFromAccess(t *testing.T) {
	t.Parallel()
	res := &nokkuv1.GetMyAccessResponse{
		Subject: &nokkuv1.GetMyAccessResponse_User{User: &nokkuv1.User{Id: new("u"), Name: new("alice")}},
		CertificateAuthorities: []*nokkuv1.CertificateAuthority{
			{Id: new(caID), Name: new("ssh"), PublicKey: new("ssh-ed25519 AAAA")},
			{Id: new("not-a-uuid"), Name: new("odd")},
		},
		Targets: []*nokkuv1.Target{
			{Id: new(targetID), CaId: new(caID), Name: new("web")},
			{Id: new("../../etc"), CaId: new(caID), Name: new("evil")},
			{Id: new("{" + targetID + "}"), CaId: new(caID), Name: new("braces")},
		},
	}

	c := FromAccess(res)
	require.NotNil(t, c.User)
	assert.Equal(t, "alice", c.User.Name)
	require.Len(t, c.CAs, 1, "non-canonical CA ids are dropped")
	require.Len(t, c.Targets, 1, "non-canonical ids are dropped")
	assert.Equal(t, "web", c.Targets[0].Name)
	assert.Equal(t, caID, c.Targets[0].CAID)
}

// Names are printed by nk ls, nk doctor and in warnings.
func TestFromAccessDropsControlCharacters(t *testing.T) {
	t.Parallel()
	c := FromAccess(&nokkuv1.GetMyAccessResponse{
		Subject: &nokkuv1.GetMyAccessResponse_User{
			User: &nokkuv1.User{Id: new("u"), Name: new("al\x1b[2Jice"), Email: new("a@b.example\x07")},
		},
		CertificateAuthorities: []*nokkuv1.CertificateAuthority{{Id: new(caID), Name: new("ssh\x1b[31m")}},
		Targets: []*nokkuv1.Target{{
			Id: new(targetID), CaId: new(caID), Name: new("web\x1b]0;owned\x07"),
			Usernames: []string{"ro\x1bot", "alice"}, Endpoints: []string{"10.0.0.5\r\n"},
		}},
	})

	assert.Equal(t, &User{ID: "u", Name: "al[2Jice", Email: "a@b.example"}, c.User)
	assert.Equal(t, "ssh[31m", c.CAs[0].Name)
	require.Len(t, c.Targets, 1)
	assert.Equal(t, "web]0;owned", c.Targets[0].Name)
	assert.Equal(t, []string{"root", "alice"}, c.Targets[0].Usernames)
	assert.Equal(t, []string{"10.0.0.5"}, c.Targets[0].Endpoints)
}
