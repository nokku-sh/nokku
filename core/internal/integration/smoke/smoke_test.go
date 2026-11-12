//go:build integration && smoke

// Package smoke_test runs the real nokku, nk and nokkud against a throwaway
// Postgres, Mailpit and daemon container. Every container, port and HOME is its
// own, so the dev stack and the real ~/.ssh stay out of it.
package smoke_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/ssh/agent"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

const (
	// compose.dev.yml runs the same version.
	mailpitImage = "docker.io/axllent/mailpit:v1.31.6"
	daemonImage  = "nokkud:smoke"
	smokeLabel   = "sh.nokku.smoke=true"

	ownerEmail = "owner@smoke.test"
	// The container enrolls under its hostname, dev is its one account.
	serverName = "smoke-box"
	account    = "dev"
	login      = account + "@" + serverName

	// What the web terminal types. It prints smoke-web, its own echo does not.
	webCommand = "echo smoke-''web"
	// The close code of the terminal websocket when the shell ended on its own.
	shellExited websocket.StatusCode = 4000
)

var (
	adminLink = regexp.MustCompile(`/login/verify\?token=(\S+)`)
	userCode  = regexp.MustCompile(`the code (\S+) there`)
)

// smoke is what the phases share. Each phase fills in what the later ones need.
type smoke struct {
	core     core
	home     nkHome
	platform *jobPlatform
	// The daemon container, removed when the test ends.
	container string
	sshPort   string

	// The owner's browser. Its cookie jar holds the session.
	browser        *http.Client
	client         *connect.Client
	auth           nokkuv1connect.AuthServiceClient
	joinTokens     nokkuv1connect.JoinTokenServiceClient
	daemons        nokkuv1connect.DaemonServiceClient
	targets        nokkuv1connect.TargetServiceClient
	targetAccounts nokkuv1connect.TargetAccountServiceClient
	recordings     nokkuv1connect.RecordingServiceClient
	util           nokkuv1connect.UtilServiceClient

	owner      *nokkuv1.User
	daemon     *nokkuv1.Daemon
	target     *nokkuv1.Target
	devAccount *nokkuv1.TargetAccount
	webSession string
}

// core is the nokku binary, on plain HTTP and localhost like a dev setup.
type core struct {
	binary string
	url    string
	// admin-link runs with the server's environment.
	env []string
	dir string
	// The whole test, a server started in a phase must outlive it.
	t *testing.T
	// stop shuts the running server down and waits for it.
	stop func()
}

// nkHome is where nk and ssh run. Its own HOME keeps the real ~/.ssh,
// ~/.config/nk and ssh agent out of it.
type nkHome struct {
	dir       string
	nkBinary  string
	sshBinary string
	env       []string
}

// lockedBuffer collects a process's output while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}

// TestSmoke takes one owner from the first sign-in to a revoked session.
func TestSmoke(t *testing.T) {
	s := setUp(t)
	for _, phase := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"owner signs in with admin-link", s.signInOwner},
		{"daemon enrolls and comes online", s.enrollDaemon},
		{"owner is granted the dev account", s.grantAccount},
		{"nk signs in with the device flow", s.loginNK},
		{"ssh connects directly", s.sshDirect},
		{"ssh connects through the relay", s.sshRelay},
		{"web terminal runs a shell", s.webTerminal},
		{"sessions are recorded", s.checkRecordings},
		{"ssh connects while the core is down", s.sshWithoutCore},
		{"an upgrade waits for the open session", s.upgradeWaitsForSessions},
		{"revoking the grant ends the session", s.revokeGrant},
		{"audit log holds the flows", s.checkAuditLog},
		{"a CI job reaches the server with no stored secret", s.ciJob},
	} {
		require.True(t, t.Run(phase.name, phase.run), "the phases after %q build on it", phase.name)
	}
}

// setUp builds the binaries and starts what every phase runs against.
func setUp(t *testing.T) *smoke {
	sshBinary, err := exec.LookPath("ssh")
	require.NoError(t, err, "the smoke test drives OpenSSH")
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	require.NoError(t, err)

	bin, imageDir := t.TempDir(), t.TempDir()
	goBuild(t, repo, bin, "./core/cmd/nokku", "./cli/cmd/nk")
	goBuild(t, repo, imageDir, "./daemon/cmd/nokkud")
	// The local daemon/Dockerfile build, from a context of the binary alone.
	run(t, exec.CommandContext(t.Context(), "docker", "build", "--quiet",
		"--file", filepath.Join(repo, "daemon", "Dockerfile"),
		"--build-arg", "BINARY=nokkud",
		"--label", smokeLabel,
		"--tag", daemonImage,
		imageDir,
	))
	// A new binary moves the tag, the image of the run before is left dangling.
	run(t, exec.CommandContext(t.Context(), "docker", "image", "prune", "--force", "--filter", "label="+smokeLabel))

	smtpHost, smtpPort := startMailpit(t)
	platform := startJobPlatform(t)
	s := &smoke{
		core:      startCore(t, bin, smtpHost, smtpPort, platform.certFile),
		home:      newNKHome(t, bin, sshBinary),
		platform:  platform,
		container: "nokkud-smoke-" + strings.ToLower(rand.Text()[:8]),
		sshPort:   freePort(t),
	}
	t.Cleanup(func() { removeContainer(t, s.container) })

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	// Bounded like the child processes, see bounded.
	s.browser = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	client := connect.NewClient(connecthttp.NewTransport(s.browser, s.core.url))
	s.client = client
	s.auth = nokkuv1connect.NewAuthServiceClient(client)
	s.joinTokens = nokkuv1connect.NewJoinTokenServiceClient(client)
	s.daemons = nokkuv1connect.NewDaemonServiceClient(client)
	s.targets = nokkuv1connect.NewTargetServiceClient(client)
	s.targetAccounts = nokkuv1connect.NewTargetAccountServiceClient(client)
	s.recordings = nokkuv1connect.NewRecordingServiceClient(client)
	s.util = nokkuv1connect.NewUtilServiceClient(client)
	return s
}

func (s *smoke) signInOwner(t *testing.T) {
	out := run(t, s.core.command(bounded(t), "admin-link"))
	link := adminLink.FindStringSubmatch(out)
	require.NotNil(t, link, "admin-link printed no sign-in link: %s", out)

	// The link opens the SPA, which trades the token for the cookie here.
	res, err := s.auth.ConsumeMagicLink(t.Context(), &nokkuv1.ConsumeMagicLinkRequest{Token: &link[1]})
	require.NoError(t, err)
	s.owner = res.GetUser()
	assert.Equal(t, ownerEmail, s.owner.GetEmail())
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, s.owner.GetRole())

	base, err := url.Parse(s.core.url)
	require.NoError(t, err)
	cookies := s.browser.Jar.Cookies(base)
	assert.True(t, slices.ContainsFunc(cookies, func(c *http.Cookie) bool { return c.Name == "nokku_session" }),
		"the sign-in set no session cookie, the browser holds %v", cookies)
}

func (s *smoke) enrollDaemon(t *testing.T) {
	created, err := s.joinTokens.CreateJoinToken(t.Context(), &nokkuv1.CreateJoinTokenRequest{
		Label:       new("smoke"),
		MaxUses:     new(int32(1)),
		AutoApprove: new(true),
	})
	require.NoError(t, err)

	// Host networking, the daemon takes plain HTTP from localhost only. It
	// listens on every interface because nk dials the host addresses it
	// advertises.
	docker := exec.CommandContext(bounded(t), "docker", "run", "--detach",
		"--name", s.container,
		"--label", smokeLabel,
		"--hostname", serverName,
		"--network", "host",
		"--env", "NOKKUD_API_URL="+s.core.url,
		"--env", "NOKKUD_SSH_ADDR=0.0.0.0:"+s.sshPort,
		"--env", "NOKKUD_ENROLL_TOKEN",
		daemonImage,
	)
	// Not on the command line, any local user can read the token there.
	docker.Env = append(os.Environ(), "NOKKUD_ENROLL_TOKEN="+created.GetSecret())
	run(t, docker)

	waitFor(t, time.Minute, func() bool {
		res, err := s.daemons.ListDaemons(t.Context(), &nokkuv1.ListDaemonsRequest{Limit: new(int32(10))})
		require.NoError(t, err)
		i := slices.IndexFunc(res.GetDaemons(), func(d *nokkuv1.Daemon) bool {
			return d.GetName() == serverName && d.GetOnline() &&
				d.GetStatus() == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
		})
		if i >= 0 {
			s.daemon = res.GetDaemons()[i]
		}
		return s.daemon != nil
	}, "%s never showed as accepted and online", serverName)
	assert.NotEmpty(t, s.daemon.GetVersion(), "the version comes from nokkud's user agent")

	// Online means connected, the filter says the same as the daemon itself.
	online, err := s.daemons.ListDaemons(t.Context(), &nokkuv1.ListDaemonsRequest{Online: new(true)})
	require.NoError(t, err)
	assert.True(t, slices.ContainsFunc(online.GetDaemons(), func(d *nokkuv1.Daemon) bool {
		return d.GetId() == s.daemon.GetId()
	}), "the online filter left out a connected daemon")
	offline, err := s.daemons.ListDaemons(t.Context(), &nokkuv1.ListDaemonsRequest{Online: new(false)})
	require.NoError(t, err)
	assert.False(t, slices.ContainsFunc(offline.GetDaemons(), func(d *nokkuv1.Daemon) bool {
		return d.GetId() == s.daemon.GetId()
	}), "the offline filter took a connected daemon")

	res, err := s.targets.ListTargets(t.Context(), &nokkuv1.ListTargetsRequest{DaemonId: new(s.daemon.GetId())})
	require.NoError(t, err)
	require.Len(t, res.GetTargets(), 1, "the daemon has no target of its own")
	s.target = res.GetTargets()[0]
}

func (s *smoke) grantAccount(t *testing.T) {
	// Accounts come from the daemon's sync, the grant goes on the reported one.
	waitFor(t, time.Minute, func() bool {
		res, err := s.targetAccounts.ListTargetAccounts(t.Context(), &nokkuv1.ListTargetAccountsRequest{
			TargetId: new(s.target.GetId()),
		})
		require.NoError(t, err)
		i := slices.IndexFunc(res.GetAccounts(), func(a *nokkuv1.TargetAccount) bool {
			return a.GetUsername() == account
		})
		if i >= 0 {
			s.devAccount = res.GetAccounts()[i]
		}
		return s.devAccount != nil
	}, "the daemon never reported its %s account", account)

	_, err := s.targetAccounts.AddSubjects(t.Context(), &nokkuv1.AddSubjectsRequest{
		Id:         new(s.devAccount.GetId()),
		SubjectIds: []string{s.owner.GetId()},
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
	})
	require.NoError(t, err)

	// ssh checks the host certificate, the daemon gets it after its first sync.
	waitFor(t, time.Minute, func() bool { return len(s.auditLogs(t, "SignHostCertificate")) > 0 },
		"the daemon never got a host certificate")
}

func (s *smoke) loginNK(t *testing.T) {
	var out lockedBuffer
	nk := s.home.nk(t, "--api", s.core.url, "login")
	nk.Stdout, nk.Stderr = &out, &out
	require.NoError(t, nk.Start())

	var code string
	waitFor(t, 30*time.Second, func() bool {
		m := userCode.FindStringSubmatch(out.String())
		if m != nil {
			code = m[1]
		}
		return m != nil
	}, "nk printed no code to confirm: %s", &out)

	// What the device page posts when the owner approves the code, then where it sends the browser.
	res, err := s.browser.PostForm(s.core.url+"/auth/device/verify", url.Values{"user_code": {code}})
	require.NoError(t, err)
	var approved struct {
		Redirect string `json:"redirect"`
	}
	err = json.NewDecoder(res.Body).Decode(&approved)
	_ = res.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "the approval was refused")
	require.True(
		t,
		strings.HasPrefix(approved.Redirect, "http://127.0.0.1:"),
		"no way back to nk: %q",
		approved.Redirect,
	)
	back, err := http.Get(approved.Redirect)
	require.NoError(t, err)
	_ = back.Body.Close()
	require.Equal(t, http.StatusOK, back.StatusCode, "nk did not take the browser's answer")

	require.NoError(t, nk.Wait(), "nk login: %s", &out)
	assert.Contains(t, out.String(), "Signed in as "+ownerEmail+", 1 servers available")
	config, err := os.ReadFile(filepath.Join(s.home.dir, ".config", "nk", "ssh_config"))
	require.NoError(t, err)
	assert.Contains(t, string(config), "Host "+serverName+"\n", "nk wrote no ssh config for the server")
}

func (s *smoke) sshDirect(t *testing.T) {
	res, err := s.targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: new(s.target.GetId())})
	require.NoError(t, err)
	endpoints := res.GetTarget().GetEndpoints()
	relays := s.relayOpens(t)

	out, err := s.home.ssh(t, login, "echo smoke-direct").CombinedOutput()
	require.NoError(t, err, "ssh: %s", out)
	assert.Contains(t, string(out), "smoke-direct")

	if len(endpoints) == 0 {
		t.Skip("the daemon advertised no address of this machine, so nk could only take the relay")
	}
	assert.Equal(t, relays, s.relayOpens(t), "nk took the relay, not one of %v", endpoints)
}

func (s *smoke) sshRelay(t *testing.T) {
	relays := s.relayOpens(t)
	// ssh takes the first value it gets, so this goes before the ProxyCommand
	// of nk's config.
	proxy := "ProxyCommand=" + s.home.nkBinary + " proxy --relay " + s.target.GetId() + " %p"

	out, err := s.home.ssh(t, "-o", proxy, login, "echo smoke-relay").CombinedOutput()
	require.NoError(t, err, "ssh: %s", out)
	assert.Contains(t, string(out), "smoke-relay")
	assert.Equal(t, relays+1, s.relayOpens(t), "the session did not go through the relay")
}

func (s *smoke) webTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	created, err := s.daemons.CreateSession(ctx, &nokkuv1.CreateSessionRequest{
		DaemonId: new(s.daemon.GetId()),
		Username: new(account),
	})
	require.NoError(t, err)
	s.webSession = created.GetSession().GetSessionId()

	// As the web app opens it, with the session cookie and its own origin.
	ws, _, err := websocket.Dial(ctx, s.core.url+"/terminal/ws?session_id="+s.webSession, &websocket.DialOptions{
		HTTPClient: s.browser,
		HTTPHeader: http.Header{"Origin": {s.core.url}},
	})
	require.NoError(t, err)
	defer func() { _ = ws.CloseNow() }()
	require.NoError(t, ws.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":120,"rows":40}`)))

	// xterm sends Enter as a carriage return.
	require.NoError(t, ws.Write(ctx, websocket.MessageBinary, []byte(webCommand+"\r")))
	var screen strings.Builder
	for !strings.Contains(screen.String(), "smoke-web") {
		_, data, err := ws.Read(ctx)
		require.NoError(t, err, "the terminal showed: %q", screen.String())
		screen.Write(data)
	}

	require.NoError(t, ws.Write(ctx, websocket.MessageBinary, []byte("exit\r")))
	for err == nil {
		_, _, err = ws.Read(ctx)
	}
	assert.Equal(t, shellExited, websocket.CloseStatus(err), "the socket did not report the shell's exit: %v", err)
}

func (s *smoke) checkRecordings(t *testing.T) {
	// A session uploads its recording when it ends: direct, relay, web
	// terminal.
	var recordings []*nokkuv1.Recording
	waitFor(t, time.Minute, func() bool {
		res, err := s.recordings.ListRecordings(t.Context(), &nokkuv1.ListRecordingsRequest{
			DaemonId: new(s.daemon.GetId()),
			Limit:    new(int32(100)),
		})
		require.NoError(t, err)
		recordings = slices.DeleteFunc(res.GetRecordings(), func(r *nokkuv1.Recording) bool { return !r.GetComplete() })
		return len(recordings) >= 3
	}, "the three sessions were not all recorded")

	casts := make(map[string]string, len(recordings))
	for _, r := range recordings {
		cast := s.cast(t, r.GetId())
		assert.True(t, strings.HasPrefix(cast, `{"version":3,`), "recording %s is no asciicast v3", r.GetId())
		casts[r.GetId()] = cast
	}
	require.Contains(t, casts, s.webSession, "the web terminal has no recording under its session id")
	// A pty records the echoed input next to the output.
	assert.Contains(t, casts[s.webSession], webCommand)
	assert.Contains(t, casts[s.webSession], "smoke-web")
	// ssh without a pty records the output only.
	all := strings.Join(slices.Collect(maps.Values(casts)), "\n")
	assert.Contains(t, all, "smoke-direct")
	assert.Contains(t, all, "smoke-relay")
}

// A certificate nk holds logs in on a server it reaches directly, with no core
// to ask. The daemon enforces the access it last synced.
func (s *smoke) sshWithoutCore(t *testing.T) {
	res, err := s.targets.GetTarget(t.Context(), &nokkuv1.GetTargetRequest{Id: new(s.target.GetId())})
	require.NoError(t, err)
	if len(res.GetTarget().GetEndpoints()) == 0 {
		t.Skip("the daemon advertised no address of this machine, and the relay needs the core")
	}

	s.core.stop()
	require.False(t, healthy(s.core.url), "the core still answers")
	out, sshErr := s.home.ssh(t, login, "echo smoke-offline").CombinedOutput()
	// Back up before the verdict, the later phases need it either way.
	s.core.start()
	require.NoError(t, sshErr, "ssh without the core: %s", out)
	assert.Contains(t, string(out), "smoke-offline")

	waitFor(t, 2*time.Minute, func() bool {
		res, err := s.daemons.ListDaemons(t.Context(), &nokkuv1.ListDaemonsRequest{Online: new(true)})
		require.NoError(t, err)
		return slices.ContainsFunc(res.GetDaemons(), func(d *nokkuv1.Daemon) bool {
			return d.GetId() == s.daemon.GetId()
		})
	}, "the daemon never came back to the restarted core")
}

// An upgrade renames a new binary over the running one, and postinstall.sh then
// sends USR1. The open session runs on, helpers start from the new binary, and
// the daemon restarts after the session with its enrollment.
func (s *smoke) upgradeWaitsForSessions(t *testing.T) {
	docker := func(args ...string) string {
		out, err := exec.CommandContext(bounded(t), "docker", args...).CombinedOutput()
		require.NoError(t, err, "docker %v: %s", args, out)
		return strings.TrimSpace(string(out))
	}

	// Past a tick of the wait, so a restart would cut it.
	session := s.home.ssh(t, login, "echo smoke-open && sleep 8 && echo smoke-survived")
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.Start())
	lines := bufio.NewScanner(stdout)
	require.True(t, lines.Scan(), "the session never started")
	require.Equal(t, "smoke-open", lines.Text())

	docker("exec", s.container, "sh", "-c",
		"cp /usr/bin/nokkud /usr/bin/nokkud.new && mv /usr/bin/nokkud.new /usr/bin/nokkud")
	docker("kill", "--signal", "USR1", s.container)

	// SFTP runs in a helper, on the binary the upgrade put there.
	scp, err := exec.LookPath("scp")
	require.NoError(t, err)
	file := filepath.Join(s.home.dir, "upgrade")
	require.NoError(t, os.WriteFile(file, []byte("smoke-sftp"), 0o600))
	copied, err := s.home.command(t, scp,
		"-F", filepath.Join(s.home.dir, ".ssh", "config"), "-o", "BatchMode=yes", "-S", s.home.sshBinary,
		file, login+":/tmp/smoke-upgrade",
	).CombinedOutput()
	require.NoError(t, err, "scp during the wait: %s", copied)
	assert.Equal(t, "smoke-sftp", docker("exec", s.container, "cat", "/tmp/smoke-upgrade"))

	require.True(t, lines.Scan(), "the upgrade cut the open session")
	assert.Equal(t, "smoke-survived", lines.Text())
	require.NoError(t, session.Wait())

	assert.Equal(t, "75", docker("wait", s.container), "the unit file restarts on 75")
	docker("start", s.container)
	waitFor(t, time.Minute, func() bool {
		out, err := s.home.ssh(t, login, "echo smoke-back").CombinedOutput()
		return err == nil && strings.Contains(string(out), "smoke-back")
	}, "the server never came back")
	waitFor(t, time.Minute, func() bool {
		res, err := s.daemons.ListDaemons(t.Context(), &nokkuv1.ListDaemonsRequest{Online: new(true)})
		require.NoError(t, err)
		return slices.ContainsFunc(res.GetDaemons(), func(d *nokkuv1.Daemon) bool {
			return d.GetId() == s.daemon.GetId()
		})
	}, "the daemon came back as another enrollment")
}

func (s *smoke) revokeGrant(t *testing.T) {
	var out lockedBuffer
	held := s.home.ssh(t, login, "echo ready; sleep 120")
	held.Stdout, held.Stderr = &out, &out
	require.NoError(t, held.Start())
	ended := make(chan error, 1)
	go func() { ended <- held.Wait() }()
	waitFor(t, 30*time.Second, func() bool { return strings.Contains(out.String(), "ready") },
		"the session never started: %s", &out)
	require.Never(t, func() bool { return len(ended) > 0 }, time.Second, 100*time.Millisecond,
		"the session ended before the revoke: %s", &out)

	_, err := s.targetAccounts.RemoveSubjects(t.Context(), &nokkuv1.RemoveSubjectsRequest{
		Id:         new(s.devAccount.GetId()),
		SubjectIds: []string{s.owner.GetId()},
		Kind:       nokkuv1.SubjectKind_SUBJECT_KIND_USER.Enum(),
	})
	require.NoError(t, err)
	// A revoke is a matter of seconds. A sync change that makes it slower has to show up here.
	revoked := time.Now()
	select {
	case err = <-ended:
		require.Error(t, err, "ssh ended cleanly, the daemon should have cut it: %s", &out)
		t.Logf("the revoke ended the session after %s", time.Since(revoked).Round(time.Millisecond))
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the session outlived the revoke by 5 s")
	}

	again, err := s.home.ssh(t, login, "echo smoke-after-revoke").CombinedOutput()
	require.Error(t, err, "a new ssh got in after the revoke")
	assert.NotContains(t, string(again), "smoke-after-revoke")
	t.Logf("the new ssh was refused with: %s", bytes.TrimSpace(again))
}

func (s *smoke) checkAuditLog(t *testing.T) {
	// nokkud reports its connections by itself, a moment after they happen.
	waitFor(t, 30*time.Second, func() bool { return len(s.auditLogs(t, "ConnectionClose")) > 0 },
		"the daemon reported no connection to the audit log")
	seen := map[string]bool{}
	for _, l := range s.auditLogs(t, "Login", "SignSSHCertificate", "CreateSession", "RelayOpen", "RelayClose",
		"ConnectionOpen", "ConnectionClose") {
		if l.GetOk() {
			seen[l.GetAction()+" by "+l.GetActorKind()] = true
		}
	}
	for _, want := range []string{
		"Login by user", // the admin link
		"Login by cli",  // nk's device flow
		"SignSSHCertificate by cli",
		"CreateSession by user", // the web terminal
		"RelayOpen by cli",
		"RelayClose by cli",
		"ConnectionOpen by daemon", // each SSH login, as nokkud saw it
		"ConnectionClose by daemon",
	} {
		assert.True(t, seen[want], "no %q in the audit log, it holds %v", want, slices.Sorted(maps.Keys(seen)))
	}
}

// relayOpens counts the sessions the core relayed so far.
func (s *smoke) relayOpens(t *testing.T) int {
	return len(s.auditLogs(t, "RelayOpen"))
}

func (s *smoke) auditLogs(t *testing.T, actions ...string) []*nokkuv1.EventLog {
	res, err := s.util.ListAuditLogs(t.Context(), &nokkuv1.ListAuditLogsRequest{
		Limit:  new(int32(100)),
		Filter: &nokkuv1.AuditLogFilter{Actions: actions},
	})
	require.NoError(t, err)
	return res.GetLogs()
}

// cast fetches a recording like the web player, gzipped asciicast in chunks.
func (s *smoke) cast(t *testing.T, id string) string {
	stream, err := s.recordings.GetRecording(t.Context(), &nokkuv1.GetRecordingRequest{RecordingId: &id})
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()
	var compressed bytes.Buffer
	for {
		msg, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "read recording %s", id)
		compressed.Write(msg.GetChunk())
	}
	r, err := gzip.NewReader(&compressed)
	require.NoError(t, err, "recording %s is not gzip", id)
	cast, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(cast)
}

func startCore(t *testing.T, bin, smtpHost, smtpPort, platformCert string) core {
	port := freePort(t)
	c := core{
		binary: filepath.Join(bin, "nokku"),
		url:    "http://localhost:" + port,
		// Nothing comes from the developer's shell, so it cannot point the core
		// at real mail, a license server, KMS or SSO.
		env: []string{
			"HOME=" + t.TempDir(),
			"NOKKU_BASE_URL=localhost:" + port,
			"NOKKU_PORT=" + port,
			"NOKKU_SECRET=smoke-secret-0123456789-0123456789",
			"NOKKU_ADMIN_EMAIL=" + ownerEmail,
			"NOKKU_SMTP_HOST=" + smtpHost,
			"NOKKU_SMTP_PORT=" + smtpPort,
			"NOKKU_SMTP_FROM=nokku@smoke.test",
			"NOKKU_STORAGE_URL=file://" + t.TempDir(),
			"NOKKU_LICENSE_OFFLINE=true",
			// The job platform listens on loopback, behind its own certificate.
			"SSL_CERT_FILE=" + platformCert,
		},
		dir: t.TempDir(),
		t:   t,
	}
	// testenv.Postgres pointed these at its container.
	for _, key := range []string{"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE"} {
		c.env = append(c.env, key+"="+os.Getenv(key))
	}

	c.start()
	return c
}

// start runs the server until the test ends or stop is called.
func (c *core) start() {
	t := c.t
	ctx, cancel := context.WithCancel(t.Context())
	server := c.command(ctx)
	server.Dir = c.dir
	exited := startLogged(t, server)
	c.stop = func() {
		cancel()
		<-exited
	}
	waitFor(t, time.Minute, func() bool {
		require.False(t, closed(exited), "the core exited at start")
		return healthy(c.url)
	}, "the core never answered /healthz")
}

func (c *core) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Env = c.env
	return cmd
}

func newNKHome(t *testing.T, bin, sshBinary string) nkHome {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "run")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	h := nkHome{dir: dir, nkBinary: filepath.Join(bin, "nk"), sshBinary: sshBinary, env: []string{
		"HOME=" + dir,
		"XDG_CONFIG_HOME=" + filepath.Join(dir, ".config"),
		"XDG_RUNTIME_DIR=" + runtimeDir,
		// The binaries alone. xdg-open from PATH would open a real browser.
		"PATH=" + bin,
		// A display makes nk sign in through 127.0.0.1, the path people take.
		"DISPLAY=:99",
		// ssh runs ProxyCommand and Match exec through it.
		"SHELL=/bin/sh",
	}}
	t.Cleanup(func() { stopAgent(filepath.Join(dir, ".config", "nk", "agent.sock")) })
	return h
}

func (h nkHome) nk(t *testing.T, args ...string) *exec.Cmd {
	return h.command(t, h.nkBinary, args...)
}

// ssh runs OpenSSH on nk's config alone. ssh finds ~ in the passwd entry, not
// in HOME, so -F keeps ~/.ssh out.
func (h nkHome) ssh(t *testing.T, args ...string) *exec.Cmd {
	args = append([]string{"-F", filepath.Join(h.dir, ".ssh", "config"), "-o", "BatchMode=yes"}, args...)
	return h.command(t, h.sshBinary, args...)
}

func (h nkHome) command(t *testing.T, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(bounded(t), binary, args...)
	cmd.Env = h.env
	// ssh hands its output to nk proxy, a child holding it must not stall us.
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// stopAgent ends the agent nk proxy started, which would outlive the test.
func stopAgent(socket string) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = agent.NewClient(conn).Extension("shutdown@nokku.sh", nil)
}

// startMailpit returns the SMTP address of the relay the core sends mail to.
func startMailpit(t *testing.T) (host, port string) {
	c, err := testcontainers.Run(t.Context(), mailpitImage,
		testcontainers.WithExposedPorts("1025/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("1025/tcp")),
	)
	testcontainers.CleanupContainer(t, c)
	require.NoError(t, err, "start mailpit")
	endpoint, err := c.PortEndpoint(t.Context(), "1025/tcp", "")
	require.NoError(t, err)
	host, port, err = net.SplitHostPort(endpoint)
	require.NoError(t, err)
	return host, port
}

// removeContainer runs in a cleanup, after the test's context ended.
func removeContainer(t *testing.T, name string) {
	if t.Failed() {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Logf("daemon log:\n%s", logs)
	}
	_ = exec.Command("docker", "rm", "--force", "--volumes", name).Run()
}

// goBuild builds static binaries into dir, like the release does.
func goBuild(t *testing.T, repo, dir string, pkgs ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", append([]string{"build", "-o", dir + "/"}, pkgs...)...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	run(t, cmd)
}

// run runs cmd to its end and returns its output. A failure fails the test.
func run(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", cmd, out)
	return string(out)
}

// startLogged runs cmd until the test ends. A failed test prints its log.
func startLogged(t *testing.T, cmd *exec.Cmd) (exited <-chan struct{}) {
	t.Helper()
	log, err := os.Create(filepath.Join(t.TempDir(), "output.log"))
	require.NoError(t, err)
	cmd.Stdout, cmd.Stderr = log, log
	// The context ends with the test. An interrupt shuts the binary down.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	require.NoError(t, cmd.Start())

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		<-done
		out, _ := os.ReadFile(log.Name())
		// The database outlives a shutdown, or the last requests lose audit
		// events.
		assert.NotContains(t, string(out), "closed pool",
			"%s used the database after it closed", filepath.Base(cmd.Path))
		if t.Failed() {
			t.Logf("%s log:\n%s", filepath.Base(cmd.Path), out)
		}
		_ = log.Close()
	})
	return done
}

// bounded is the test's context with a deadline. A hang must fail its phase,
// the go test timeout skips the cleanups.
func bounded(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// waitFor polls cond on the test's goroutine, so cond may fail the test and set
// what the test reads after.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msgAndArgs ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			require.FailNow(t, "timed out after "+timeout.String(), msgAndArgs...)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func healthy(base string) bool {
	res, err := http.Get(base + "/healthz")
	if err != nil {
		return false
	}
	_ = res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// freePort is a TCP port nothing listens on right now, on any interface.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	return port
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
