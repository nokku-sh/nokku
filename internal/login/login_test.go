package login

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidUsername(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		valid bool
	}{
		{"root", true},
		{"deploy", true},
		{"_svc", true},
		{"john.doe", true},
		{"John", true},
		{"ec2-user", true},
		{"machine$", true},
		{strings.Repeat("a", 32), true},
		{"", false},
		{".", false},
		{"..", false},
		{"-rf", false},
		{"0abc", false},
		{"a/b", false},
		{"a b", false},
		{"a\n", false},
		{"üser", false},
		{"a$b", false},
		{"$", false},
		{`corp\john`, false},
		{"john@corp", false},
		{"%u", false},
		{strings.Repeat("a", 33), false},
	} {
		assert.Equal(t, tt.valid, ValidUsername(tt.name), "ValidUsername(%q)", tt.name)
	}
}

// An accepted name must be safe as a path component and as one config word.
func FuzzValidUsername(f *testing.F) {
	f.Add("roxas")
	f.Add("..")
	f.Add("john.doe")
	f.Fuzz(func(t *testing.T, name string) {
		if !ValidUsername(name) {
			return
		}
		bad := name == "." || name == ".." || strings.ContainsAny(name, "/\x00 \t\r\n\"'%")
		require.False(t, bad, "ValidUsername(%q) accepted an unsafe name", name)
	})
}

func TestValidID(t *testing.T) {
	t.Parallel()
	id := "0192d6a0-7c1e-7c3a-8f3b-6f2a9f0b1c2d"
	assert.True(t, ValidID(id))
	for _, bad := range []string{
		"", "garbage", strings.ToUpper(id), "{" + id + "}", "urn:uuid:" + id,
		strings.ReplaceAll(id, "-", ""), id + "\n",
	} {
		assert.False(t, ValidID(bad), "ValidID(%q) accepted", bad)
	}
}

func TestPrincipal(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "subject@target:root", Principal("subject", "target", "root"))
}

func TestParsePrincipal(t *testing.T) {
	t.Parallel()
	subject := "0192d6a0-7c1e-7c3a-8f3b-6f2a9f0b1c2d"
	target := "0192d6a0-7c1e-7c3a-8f3b-6f2a9f0b1c2e"
	got, ok := ParsePrincipal(Principal(subject, target, "deploy"))
	assert.True(t, ok)
	assert.Equal(t, Parts{SubjectID: subject, TargetID: target, Username: "deploy"}, got)
	for _, bad := range []string{
		"", "deploy", subject + "@" + target, subject + "@" + target + ":",
		"root@" + target + ":deploy", subject + "@host:deploy",
	} {
		_, ok = ParsePrincipal(bad)
		assert.False(t, ok, "ParsePrincipal(%q) accepted", bad)
	}
}

// The command prints the principal the core signs for sshd's account.
func TestPrincipalsCommand(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "server:root", ServerPrincipal("server", "root"))
	assert.Equal(t,
		"AuthorizedPrincipalsCommand /bin/echo server:%u\nAuthorizedPrincipalsCommandUser nobody\n",
		PrincipalsCommand("server"))
}

func TestAccounts(t *testing.T) {
	t.Parallel()
	got := Accounts(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"sync:x:5:0:sync:/sbin:/bin/sync",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"bob:x:1001:1001:Bob:/home/bob:/usr/bin/false",
		"carol:x:1003:1003:Carol:/home/carol:/bin/zsh",
		"carol:x:1003:1003:Carol again from LDAP:/home/carol:/bin/zsh",
		"machine$:x:1004:1004::/nonexistent:/bin/sh",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"..:x:1005:1005::/tmp:/bin/sh",
		"we'ird:x:1006:1006::/tmp:/bin/sh",
		"1user:x:1007:1007::/tmp:/bin/sh",
		"extra:x:1008:1008::/tmp:/bin/sh:field",
		"broken:fewer:fields",
		"nauid:x:notanumber:0:x:/home/x:/bin/sh",
		"",
	}, "\n"))
	assert.Equal(t, []string{"alice", "carol", "machine$", "root"}, got)
	assert.Empty(t, Accounts(""))
}

// Sorted before the cap, so the accounts past it are always the same ones.
func TestAccountsPastTheCap(t *testing.T) {
	t.Parallel()
	var passwd strings.Builder
	for i := range 250 {
		fmt.Fprintf(&passwd, "user%03d:x:%d:%d::/home/u:/bin/bash\n", 249-i, 1000+i, 1000+i)
	}
	got := Accounts(passwd.String())
	assert.Len(t, got, maxAccounts)
	assert.Equal(t, "user000", got[0])
	assert.Equal(t, "user199", got[199])
}

func TestHomeKeyFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		config string
		want   []string
	}{
		{
			"the default",
			"port 22\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\npasswordauthentication yes\n",
			[]string{".ssh/authorized_keys", ".ssh/authorized_keys2"},
		},
		{"none", "authorizedkeysfile none\n", nil},
		{"root-owned", "authorizedkeysfile /etc/ssh/authorized_keys/%u\n", nil},
		{"an absolute home path", "authorizedkeysfile %h/.ssh/authorized_keys\n", []string{"%h/.ssh/authorized_keys"}},
		{
			"mixed",
			"authorizedkeysfile /etc/ssh/authorized_keys/%u .ssh/authorized_keys\n",
			[]string{".ssh/authorized_keys"},
		},
		{"not in the output", "port 22\n", nil},
		{"a lookalike keyword", "authorizedkeyscommand /usr/bin/keys\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, HomeKeyFiles(tt.config))
		})
	}
}
