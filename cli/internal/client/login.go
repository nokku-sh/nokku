package client

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/mizuchilabs/kata/buildinfo"
	"golang.org/x/oauth2"

	"github.com/nokku-sh/nokku/internal/dpopclient"

	"github.com/nokku-sh/nokku/cli/internal/ssh"
)

const (
	maxDeviceResponse = 64 << 10
	pollRetries       = 3
)

// deviceTransport signs each request with a proof for its URL. A stale nonce is
// retried at once, the rejection came with a fresh one (RFC 9449 section 8).
type deviceTransport struct {
	dpop *dpopclient.Client
	// prefix is the path of the API URL, a proof names what follows it.
	prefix string
	next   http.RoundTripper
}

// Trusts the stored expiry. A later rejection makes Sync log in again.
func (c *Client) ensureSession(ctx context.Context, interactive bool) error {
	if c.State.IsServiceAccount() {
		return nil
	}
	// Checked on every use, so an interrupted run can't leave a session for the old key.
	if err := c.endStaleSession(ctx); err != nil {
		return err
	}
	if c.State.SessionValid() {
		return nil
	}
	if c.State.CIJob() {
		return ErrCISessionEnded
	}
	if !interactive {
		return errors.New("not signed in to Nokku")
	}
	return c.deviceLogin(ctx)
}

// The core certifies only the key a sign-in sent. The revoke is best effort, the session goes anyway.
func (c *Client) endStaleSession(ctx context.Context) error {
	if c.State.SessionKey == "" {
		return nil
	}
	if key, err := ssh.PubKey(); err != nil || key == c.State.SessionKey {
		return nil
	}
	if err := c.Logout(ctx); err != nil {
		slog.Warn("could not revoke the session of the old ssh key, sign it out under Profile, Security",
			"err", err)
	}
	c.State.SessionToken, c.State.SessionExpiresAt, c.State.SessionKey = "", time.Time{}, ""
	return c.State.Save()
}

// RFC 8628 device flow. The library handles slow_down and the code's expiry.
func (c *Client) deviceLogin(ctx context.Context) error {
	slog.Debug("starting device flow", "api", c.State.APIURL)
	ctx, cfg, err := c.deviceFlow(ctx)
	if err != nil {
		return err
	}
	// The session gets certificates for this key only.
	sshKey, err := ssh.PubKey()
	if err != nil {
		return fmt.Errorf("read the ssh key: %w", err)
	}

	d, err := beginDeviceAuth(ctx, cfg)
	if err != nil {
		return err
	}
	// The link has the code, it is shown to compare. Stderr keeps --json clean.
	fmt.Fprintf(os.Stderr, "\nSign in to Nokku in your browser. If it does not open, visit:\n  %s\n", d.VerificationURI)
	fmt.Fprintf(os.Stderr, "Confirm the code %s there. Waiting...\n", d.UserCode)
	_ = openBrowser(d.VerificationURI)

	tok, err := pollDeviceToken(ctx, cfg, d, sshKey)
	if err != nil {
		return err
	}
	c.State.SessionToken, c.State.SessionKey = tok.AccessToken, sshKey
	if !tok.Expiry.IsZero() {
		c.State.SessionExpiresAt = tok.Expiry
	}
	// Identity comes from the access sync that runs after login.
	return c.State.Save()
}

// Signing every request stops a core at another URL before a code exists.
func (c *Client) deviceFlow(ctx context.Context) (context.Context, *oauth2.Config, error) {
	base := strings.TrimRight(c.State.APIURL, "/")
	u, err := url.Parse(base)
	if err != nil {
		return ctx, nil, fmt.Errorf("the API URL %q: %w", c.State.APIURL, err)
	}
	httpc := &http.Client{
		Transport:     &deviceTransport{dpop: c.dpop, prefix: u.Path, next: c.httpc.Transport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{
		DeviceAuthURL: base + "/auth/device",
		TokenURL:      base + "/auth/device/token",
		// Auto-detect would send every poll twice, once per client id style.
		AuthStyle: oauth2.AuthStyleInParams,
	}}
	return context.WithValue(ctx, oauth2.HTTPClient, httpc), cfg, nil
}

func beginDeviceAuth(ctx context.Context, cfg *oauth2.Config) (*oauth2.DeviceAuthResponse, error) {
	d, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	d.VerificationURI = cmp.Or(d.VerificationURIComplete, d.VerificationURI)
	if d.DeviceCode == "" || d.UserCode == "" || d.VerificationURI == "" {
		return nil, errors.New("device authorization: incomplete response")
	}
	// Both are printed, and a control character can start an escape sequence.
	if strings.ContainsFunc(d.UserCode+d.VerificationURI, unicode.IsControl) {
		return nil, errors.New("device authorization: the response has control characters")
	}
	// The OS opener also launches files and custom schemes.
	u, err := url.Parse(d.VerificationURI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("device authorization: the sign-in link is not a web address")
	}
	return d, nil
}

// Restarts the library's poll after a blip, the wait takes minutes.
func pollDeviceToken(
	ctx context.Context,
	cfg *oauth2.Config,
	d *oauth2.DeviceAuthResponse,
	sshKey string,
) (*oauth2.Token, error) {
	for failures := 0; ; failures++ {
		tok, err := cfg.DeviceAccessToken(ctx, d, oauth2.SetAuthURLParam("ssh_public_key", sshKey))
		if err == nil {
			return tok, nil
		}
		slog.Debug("device flow poll", "api", cfg.Endpoint.TokenURL, "err", err)
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case !d.Expiry.IsZero() && !time.Now().Before(d.Expiry):
			return nil, errors.New("sign-in code expired, run nk login again")
		case failures < pollRetries && transient(err):
			continue
		}
		return nil, deviceError(err)
	}
}

func transient(err error) bool {
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
		return re.Response.StatusCode >= http.StatusInternalServerError
	}
	_, network := errors.AsType[*url.Error](err)
	return network && !errors.Is(err, dpopclient.ErrAPIURLMismatch)
}

func deviceError(err error) error {
	re, ok := errors.AsType[*oauth2.RetrieveError](err)
	switch {
	case !ok:
		return fmt.Errorf("device authorization: %w", err)
	case re.ErrorCode == "":
		return fmt.Errorf("device authorization: HTTP %d: %s", re.Response.StatusCode, bytes.TrimSpace(re.Body))
	case re.ErrorCode == "access_denied":
		return errors.New("sign-in was denied in the browser")
	case re.ErrorCode == "expired_token":
		return errors.New("sign-in code expired, run nk login again")
	case re.ErrorCode == "use_dpop_nonce":
		return errors.New("sign-in failed, Nokku rejected the retry with a fresh nonce, run nk login again")
	case re.ErrorCode == "invalid_dpop_proof":
		return errors.New(
			"sign-in failed, Nokku rejected this machine's proof. Check that the clock is right and run nk login again",
		)
	}
	if re.ErrorDescription != "" {
		return fmt.Errorf("device authorization failed: %s, %s", re.ErrorCode, re.ErrorDescription)
	}
	return errors.New("device authorization failed: " + re.ErrorCode)
}

func (t *deviceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, data, err := t.send(req, req.Body)
	if err != nil || req.GetBody == nil || !staleNonce(resp.StatusCode, data) {
		return resp, err
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	resp, _, err = t.send(req, body)
	return resp, err
}

// The library's first request has no context and leaves the body open.
func (t *deviceTransport) send(req *http.Request, body io.ReadCloser) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), syncTimeout)
	defer cancel()
	req = req.Clone(ctx)
	req.Body = body
	// The approval page shows it, so the user recognizes their own terminal.
	req.Header.Set("User-Agent", buildinfo.UserAgent("nk"))
	if t.dpop != nil {
		proof, err := t.dpop.Proof(ctx, req.Method, strings.TrimPrefix(req.URL.Path, t.prefix))
		if err != nil {
			if body != nil {
				_ = body.Close()
			}
			return nil, nil, err
		}
		req.Header.Set("DPoP", proof)
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	if t.dpop != nil {
		t.dpop.Learn(resp.Header.Get("DPoP-Nonce"))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDeviceResponse))
	_ = resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, data, nil
}

func staleNonce(status int, body []byte) bool {
	var answer struct {
		Error string `json:"error"`
	}
	return status == http.StatusBadRequest && json.Unmarshal(body, &answer) == nil && answer.Error == "use_dpop_nonce"
}
