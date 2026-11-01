//go:build integration

package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"
	nklogin "github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// nkSync is an admin who hands out grants and a key that asks for certificates.
type nkSync struct {
	cfg      *config.Config
	srv      *httptest.Server
	accounts nokkuv1connect.TargetAccountServiceClient
	certs    nokkuv1connect.CertificateServiceClient
	key      ed25519.PrivateKey
}

func newNKSync(t *testing.T) *nkSync {
	t.Helper()
	cfg, srv := newTestAPI(t)
	admin := clientOn(srv, header("Authorization",
		"Bearer "+seedMember(t, cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)))
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &nkSync{
		cfg:      cfg,
		srv:      srv,
		accounts: nokkuv1connect.NewTargetAccountServiceClient(admin),
		certs:    nokkuv1connect.NewCertificateServiceClient(admin),
		key:      key,
	}
}

// target is a server set up with nk sync, with one account.
func (n *nkSync) target(t *testing.T, username string) (targetID, accountID string) {
	t.Helper()
	inWorkspace(t, n.cfg, testWorkspace.ID, func(q *db.Queries) error {
		target, err := q.CreateTarget(t.Context(), &db.CreateTargetParams{Name: uniq("nk-sync")})
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	})
	res, err := n.accounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: &targetID,
		Username: &username,
	})
	require.NoError(t, err)
	return targetID, res.GetAccount().GetId()
}

func (n *nkSync) grant(t *testing.T, accountID, userID string) {
	t.Helper()
	_, err := n.accounts.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         &accountID,
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{userID},
	})
	require.NoError(t, err)
}

func (n *nkSync) revoke(t *testing.T, accountID, userID string) {
	t.Helper()
	_, err := n.accounts.RemoveSubjects(t.Context(), &nokkuv1.RemoveSubjectsRequest{
		Id:         &accountID,
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
		SubjectIds: []string{userID},
	})
	require.NoError(t, err)
}

// person is a member and the nk session that signs for them.
func (n *nkSync) person(t *testing.T) (id, token string) {
	t.Helper()
	u := seedUser(t, n.cfg, testWorkspace.ID, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	return u.ID, cliSessionFor(t, n.cfg, u)
}

func (n *nkSync) sign(t *testing.T, token, targetID string, ttl time.Duration) (*gossh.Certificate, error) {
	t.Helper()
	pub, err := gossh.NewPublicKey(n.key.Public())
	require.NoError(t, err)
	req := &nokkuv1.SignSSHCertificateRequest{
		TargetId:  &targetID,
		PublicKey: new(string(gossh.MarshalAuthorizedKey(pub))),
	}
	if ttl > 0 {
		req.Ttl = durationpb.New(ttl)
	}
	res, err := nokkuv1connect.NewCertificateServiceClient(clientOn(
		n.srv, header("Authorization", "Bearer "+token),
	)).SignSSHCertificate(t.Context(), req)
	if err != nil {
		return nil, err
	}
	signed, _, _, _, err := gossh.ParseAuthorizedKey([]byte(res.GetSignedCertificate()))
	require.NoError(t, err)
	cert, ok := signed.(*gossh.Certificate)
	require.True(t, ok, "the answer is not a certificate")
	return cert, nil
}

func lifetime(cert *gossh.Certificate) time.Duration {
	// The certificate is backdated a minute for clock skew.
	return time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0)) - time.Minute
}

// An nk sync server hears of no revoke, so certificates end within the hour.
func TestNKSyncCertificateLifetime(t *testing.T) {
	n := newNKSync(t)
	personID, token := n.person(t)

	targetID, accountID := n.target(t, "root")
	n.grant(t, accountID, personID)
	_, enrolled := enrollTestDaemon(t, n.cfg, n.srv, testWorkspace.ID, true)
	daemonAccount, err := n.accounts.AddTargetAccount(t.Context(), &nokkuv1.AddTargetAccountRequest{
		TargetId: new(enrolled.GetTargetId()),
		Username: new("root"),
	})
	require.NoError(t, err)
	n.grant(t, daemonAccount.GetAccount().GetId(), personID)

	cert, err := n.sign(t, token, targetID, 48*time.Hour)
	require.NoError(t, err)
	assert.InDelta(t, time.Hour, lifetime(cert), float64(2*time.Second), "two days asked for")
	assert.Equal(t, []string{
		nklogin.Principal(personID, targetID, "root"),
		nklogin.ServerPrincipal(targetID, "root"),
	}, cert.ValidPrincipals)

	cert, err = n.sign(t, token, enrolled.GetTargetId(), 48*time.Hour)
	require.NoError(t, err)
	assert.InDelta(t, 48*time.Hour, lifetime(cert), float64(2*time.Second), "a server with a daemon got the cap")
	assert.Equal(t, []string{nklogin.Principal(personID, enrolled.GetTargetId(), "root")}, cert.ValidPrincipals)

	setCA(t, n.cfg, n.certs, &nokkuv1.UpdateCertificateAuthorityRequest{
		UserDefaultTtl: durationpb.New(20 * time.Minute),
		UserMaxTtl:     durationpb.New(30 * time.Minute),
	})
	cert, err = n.sign(t, token, targetID, 0)
	require.NoError(t, err)
	assert.InDelta(t, 20*time.Minute, lifetime(cert), float64(2*time.Second), "the cap made a short CA longer")
}

// The core signs, real OpenSSH checks with the rule nk sync writes. Access
// changes on the core alone, a revoke stops new certificates.
func TestNKSyncServerWithOpenSSH(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available")
	}
	if _, err = exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available")
	}
	current, err := user.Current()
	require.NoError(t, err)
	if !nklogin.ValidUsername(current.Username) {
		t.Skipf("the account %q is not one Nokku handles", current.Username)
	}
	account := current.Username

	n := newNKSync(t)
	ca := workspaceCA(t, n.cfg)
	targetID, accountID := n.target(t, account)
	otherID, otherAccount := n.target(t, account)
	alice, aliceToken := n.person(t)
	bob, bobToken := n.person(t)
	n.grant(t, accountID, alice)
	n.grant(t, otherAccount, alice)

	dir := t.TempDir()
	port := startNKSyncSSHD(t, sshd, dir, ca.GetPublicKey(), targetID)
	keyFile := filepath.Join(dir, "id_ed25519")
	block, err := gossh.MarshalPrivateKey(n.key, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600))
	sshIn := func(cert *gossh.Certificate) error {
		certFile := filepath.Join(dir, "id_ed25519-cert.pub")
		require.NoError(t, os.WriteFile(certFile, gossh.MarshalAuthorizedKey(cert), 0o600))
		cmd := exec.Command("ssh", "-F", "/dev/null", "-p", port,
			"-o", "BatchMode=yes",
			"-o", "LogLevel=ERROR",
			"-o", "IdentitiesOnly=yes",
			"-o", "IdentityAgent=none",
			"-o", "IdentityFile="+keyFile,
			"-o", "CertificateFile="+certFile,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"),
			account+"@127.0.0.1", "echo in",
		)
		cmd.Env = []string{"SSH_AUTH_SOCK=", "PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		if err == nil && string(out) != "in\n" {
			return fmt.Errorf("unexpected output %q", out)
		}
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}

	cert, err := n.sign(t, aliceToken, targetID, 0)
	require.NoError(t, err)
	require.NoError(t, sshIn(cert), "the certificate for this server and account")

	_, err = n.sign(t, bobToken, targetID, 0)
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "bob has no grant yet, %v", err)
	n.grant(t, accountID, bob)
	cert, err = n.sign(t, bobToken, targetID, 0)
	require.NoError(t, err)
	require.NoError(t, sshIn(cert), "a new grant needs no change on the server")

	cert, err = n.sign(t, aliceToken, otherID, 0)
	require.NoError(t, err)
	require.Error(t, sshIn(cert), "a certificate for another server on the same CA got in")

	n.revoke(t, accountID, alice)
	_, err = n.sign(t, aliceToken, targetID, 0)
	assert.Equal(
		t,
		connect.CodePermissionDenied,
		connect.CodeOf(err),
		"a revoked grant still got a certificate, %v",
		err,
	)
}

// startNKSyncSSHD runs sshd with nk sync's rule and returns its port.
func startNKSyncSSHD(t *testing.T, sshd, dir, caKey, targetID string) string {
	t.Helper()
	hostKey := filepath.Join(dir, "host_key")
	out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput()
	require.NoError(t, err, "ssh-keygen: %s", out)
	caFile := filepath.Join(dir, "nokku_ca.pub")
	require.NoError(t, os.WriteFile(caFile, []byte(caKey+"\n"), 0o600))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, ln.Close())

	rule := nklogin.PrincipalsCommand(targetID)
	// Only root can switch to nobody.
	if os.Geteuid() != 0 {
		current, err := user.Current()
		require.NoError(t, err)
		rule = strings.Replace(
			rule,
			"AuthorizedPrincipalsCommandUser nobody",
			"AuthorizedPrincipalsCommandUser "+current.Username,
			1,
		)
	}
	config := fmt.Sprintf("Port %s\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nUsePAM no\n"+
		"PasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthorizedKeysFile none\nStrictModes no\n"+
		"TrustedUserCAKeys %s\n%s",
		port, hostKey, filepath.Join(dir, "sshd.pid"), caFile, rule)
	cfgFile := filepath.Join(dir, "sshd_config")
	require.NoError(t, os.WriteFile(cfgFile, []byte(config), 0o600))

	logFile, err := os.Create(filepath.Join(dir, "sshd.log"))
	require.NoError(t, err)
	cmd := exec.Command(sshd, "-f", cfgFile, "-D", "-e")
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start(), "start sshd")
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(dir, "sshd.log"))
			t.Logf("sshd log:\n%s", data)
		}
	})

	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
		}
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "sshd did not start")
	return port
}
