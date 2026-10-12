package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os/user"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// Canceling ctx fails Receive, like a canceled connect stream.
type fakeRelayStream struct {
	ctx  context.Context
	sent chan *nokkuv1.DaemonRelayRequest
	recv chan *nokkuv1.DaemonRelayResponse
}

// Send copies the frame like the real stream. The ssh transport reuses its write buffer.
func (s *fakeRelayStream) Send(req *nokkuv1.DaemonRelayRequest) error {
	s.sent <- proto.CloneOf(req)
	return nil
}

func (s *fakeRelayStream) Receive() (*nokkuv1.DaemonRelayResponse, error) {
	select {
	case msg := <-s.recv:
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func newTestRelayConn(t *testing.T) (*relayConn, *fakeRelayStream) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	stream := &fakeRelayStream{
		ctx:  ctx,
		sent: make(chan *nokkuv1.DaemonRelayRequest, 8),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 8),
	}
	return &relayConn{stream: stream, cancel: cancel}, stream
}

func dataFrame(data string) *nokkuv1.DaemonRelayResponse {
	return &nokkuv1.DaemonRelayResponse{Msg: &nokkuv1.DaemonRelayResponse_Data{Data: []byte(data)}}
}

func TestClientAddr(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	for addr, want := range map[string]string{
		"203.0.113.7":       "203.0.113.7:0",
		"203.0.113.7:51000": "203.0.113.7:51000",
		"2001:db8::1":       "[2001:db8::1]:0",
		"":                  "0.0.0.0:0",
		"not an address":    "0.0.0.0:0",
	} {
		got := clientAddr(addr)
		is.Equal(want, got.String(), addr)
		is.IsType(&net.TCPAddr{}, got, "source-address options need a TCP address")
	}
}

func TestRelayConnRead(t *testing.T) {
	t.Parallel()
	conn, stream := newTestRelayConn(t)
	stream.recv <- dataFrame("hello ")
	stream.recv <- dataFrame("sshd")
	stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	}

	buf := make([]byte, 4)
	var got []byte
	for {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
	}
	assert.Equal(t, "hello sshd", string(got))
}

func TestRelayConnWriteAndClose(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	conn, stream := newTestRelayConn(t)

	n, err := conn.Write([]byte("hello backend"))
	require.NoError(t, err)
	is.Equal(len("hello backend"), n)
	is.Equal([]byte("hello backend"), (<-stream.sent).GetData())

	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close(), "closing twice")
	is.NotNil((<-stream.sent).GetClosed())
	is.Empty(stream.sent, "more than one Closed frame")

	_, err = conn.Write([]byte("late"))
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, context.Canceled, "a closed relay still reads")
}

// A deadline is what bounds a relayed peer that never finishes the handshake.
func TestRelayConnDeadline(t *testing.T) {
	t.Parallel()
	conn, stream := newTestRelayConn(t)

	// A deadline that is lifted in time leaves the connection alone.
	require.NoError(t, conn.SetDeadline(time.Now().Add(50*time.Millisecond)))
	require.NoError(t, conn.SetDeadline(time.Time{}))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, stream.ctx.Err(), "a lifted deadline ended the relay")

	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Millisecond)))
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("a read outlived its deadline")
	}
}

// The user's side of a fake relay, the mirror image of relayConn.
type userEnd struct {
	stream  *fakeRelayStream
	pending []byte
}

func (u *userEnd) Read(p []byte) (int, error) {
	for len(u.pending) == 0 {
		select {
		case req := <-u.stream.sent:
			if req.GetClosed() != nil {
				return 0, io.EOF
			}
			u.pending = req.GetData()
		case <-u.stream.ctx.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, u.pending)
	u.pending = u.pending[n:]
	return n, nil
}

func (u *userEnd) Write(p []byte) (int, error) {
	select {
	case u.stream.recv <- dataFrame(string(p)):
		return len(p), nil
	case <-u.stream.ctx.Done():
		return 0, net.ErrClosed
	}
}

// Close tells the daemon the user is gone, as the backend does.
func (u *userEnd) Close() error {
	select {
	case u.stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	}:
	case <-u.stream.ctx.Done():
	}
	return nil
}

func (u *userEnd) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (u *userEnd) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (u *userEnd) SetDeadline(time.Time) error      { return nil }
func (u *userEnd) SetReadDeadline(time.Time) error  { return nil }
func (u *userEnd) SetWriteDeadline(time.Time) error { return nil }

func TestRelayServesSSH(t *testing.T) {
	must := require.New(t)
	c := newSyncClient(t, &fakeBackend{})
	cur, err := user.Current()
	must.NoError(err)

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	must.NoError(err)
	caKey, err := ssh.NewPublicKey(caPub)
	must.NoError(err)
	c.cache.Replace(map[string][]string{cur.Username: {"subject-1"}}, nil, "", nil, 1)
	c.srv.SetTrust(string(ssh.MarshalAuthorizedKey(caKey)), nil)

	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err)
	userSigner, err := ssh.NewSignerFromKey(userPriv)
	must.NoError(err)
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"subject-1"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	must.NoError(cert.SignCert(rand.Reader, caSigner))
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	must.NoError(err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := &fakeRelayStream{
		ctx:  ctx,
		sent: make(chan *nokkuv1.DaemonRelayRequest, 64),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 64),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		c.srv.ServeConn(&relayConn{
			stream: stream,
			cancel: cancel,
			remote: clientAddr("203.0.113.7"),
			local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4022},
		})
	}()

	conn, chans, reqs, err := ssh.NewClientConn(&userEnd{stream: stream}, "relay", &ssh.ClientConfig{
		User:            cur.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	})
	must.NoError(err, "ssh over the relay")
	client := ssh.NewClient(conn, chans, reqs)
	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("echo $SSH_CONNECTION")
	must.NoError(err)
	assert.Equal(t, "203.0.113.7 0 127.0.0.1 4022\n", string(out))

	must.NoError(client.Close())
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the sshd kept serving a relay whose user left")
	}
}
