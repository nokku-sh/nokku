package client

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokku/internal/dpopclient"
)

// A real device flow answer is a few hundred bytes.
const maxDeviceResponse = 64 << 10

// RFC 8628 device authorization response.
type deviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
}

// The stored expiry is trusted locally. A rejection shows up later as CodeUnauthenticated and Sync logs in again.
func (c *Client) ensureSession(ctx context.Context, interactive bool) error {
	if c.State.IsServiceAccount() {
		return nil
	}
	if c.State.SessionValid() {
		return nil
	}
	if !interactive {
		return errors.New("not signed in to Nokku")
	}
	return c.deviceLogin(ctx)
}

func (c *Client) deviceLogin(ctx context.Context) error {
	slog.Debug("starting device flow", "api", c.State.APIURL)

	// Fetch the nonce and canonical URL up front, so the first approved poll carries a valid proof. Best effort.
	if c.dpop != nil {
		if nonce, serverURL, err := dpopclient.FetchNonce(ctx, c.httpc, c.State.APIURL); err == nil {
			c.dpop.Learn(nonce, serverURL)
		}
	}

	d, err := c.beginDeviceAuth(ctx)
	if err != nil {
		return err
	}

	// The link already carries the code, the code is shown to compare.
	fmt.Printf("\nSign in to Nokku in your browser. If it does not open, visit:\n  %s\n", d.VerificationURI)
	fmt.Printf("Confirm the code %s there. Waiting...\n", d.UserCode)
	_ = openBrowser(ctx, d.VerificationURI)

	token, expiresIn, err := c.pollDeviceToken(ctx, d.DeviceCode, d.Interval)
	if err != nil {
		return err
	}

	c.State.SessionToken = token
	if expiresIn > 0 {
		c.State.SessionExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
	if err = c.State.Save(); err != nil {
		return err
	}

	// Identity comes from the access sync that runs after login.
	return nil
}

func (c *Client) beginDeviceAuth(ctx context.Context) (deviceAuth, error) {
	var d deviceAuth
	resp, err := c.postForm(ctx, "/auth/device", url.Values{})
	if err != nil {
		return d, err
	}
	if err = json.Unmarshal(resp, &d); err != nil {
		return d, fmt.Errorf("device authorization: %w", err)
	}
	d.VerificationURI = cmp.Or(d.VerificationURIComplete, d.VerificationURI)
	if d.DeviceCode == "" || d.UserCode == "" || d.VerificationURI == "" {
		return d, errors.New("device authorization: incomplete response")
	}
	// Both are printed, and a control character there starts an escape sequence.
	if strings.ContainsFunc(d.UserCode+d.VerificationURI, unicode.IsControl) {
		return d, errors.New("device authorization: the response has control characters")
	}
	// The link goes to the OS opener, which also launches files and custom schemes.
	u, err := url.Parse(d.VerificationURI)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return d, errors.New("device authorization: the sign-in link is not a web address")
	}
	return d, nil
}

func (c *Client) pollDeviceToken(
	ctx context.Context,
	deviceCode string,
	interval int,
) (token string, expiresIn int, err error) {
	// Cap the total wait at the grant TTL.
	timeout := time.NewTimer(15 * time.Minute)
	defer timeout.Stop()

	wait := time.Duration(interval) * time.Second
	if wait <= 0 {
		wait = 5 * time.Second
	}
	ticker := time.NewTicker(wait)
	defer ticker.Stop()

	bootstrapped, nonceRetried := false, false

	for {
		body, doErr := c.postForm(ctx, "/auth/device/token", url.Values{"device_code": {deviceCode}})

		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			Error       string `json:"error"`
		}
		decodeErr := json.Unmarshal(body, &out)

		if doErr == nil && decodeErr == nil && out.AccessToken != "" {
			return out.AccessToken, out.ExpiresIn, nil
		}
		if decodeErr != nil || out.Error == "" {
			// A transport error or an HTTP error without an RFC 8628 code won't fix itself on retry.
			if doErr != nil {
				return "", 0, doErr
			}
			// Never echo the body, a malformed response can still carry a token.
			return "", 0, errors.New("device authorization: unexpected response")
		}

		slog.Debug("device flow poll", "api", c.State.APIURL, "response", out.Error)
		switch out.Error {
		case "authorization_pending":
			// keep polling
		case "use_dpop_nonce":
			// postForm learned the fresh nonce, so retry at once. A second rejection in a row is final.
			if nonceRetried {
				return "", 0, errors.New(
					"sign-in failed, Nokku rejected the retry with a fresh nonce, run nk login again",
				)
			}
			nonceRetried = true
			continue
		case "invalid_dpop_proof":
			// The configured URL can differ from the canonical one proofs bind to, so learn it and retry once.
			if bootstrapped || c.dpop == nil {
				return "", 0, errors.New(
					"sign-in failed, Nokku rejected this machine's proof. " +
						"Check that the clock is right and run nk login again",
				)
			}
			bootstrapped = true
			nonce, serverURL, nerr := dpopclient.FetchNonce(ctx, c.httpc, c.State.APIURL)
			if nerr != nil {
				return "", 0, nerr
			}
			c.dpop.Learn(nonce, serverURL)
			continue
		case "slow_down":
			// RFC 8628 section 3.5. The server counts violations per grant and its interval keeps growing.
			wait += 5 * time.Second
			ticker.Reset(wait)
		case "access_denied":
			return "", 0, errors.New("sign-in was denied in the browser")
		case "expired_token":
			return "", 0, errors.New("sign-in code expired, run nk login again")
		default:
			return "", 0, errors.New("device authorization failed: " + out.Error)
		}

		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-ticker.C:
			nonceRetried = false
		case <-timeout.C:
			return "", 0, errors.New("sign-in timed out, run nk login again")
		}
	}
}

// The proof binds to the canonical API URL the server advertises, not the configured one the request goes to.
func (c *Client) postForm(
	ctx context.Context,
	path string,
	form url.Values,
) (body []byte, err error) {
	encoded := form.Encode()
	u := strings.TrimRight(c.State.APIURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The approval page shows it, so the user recognizes their own terminal.
	req.Header.Set("User-Agent", buildinfo.UserAgent("nk"))

	if c.dpop != nil {
		proof, perr := c.dpop.Proof(http.MethodPost, c.dpop.HtuBase()+path)
		if perr != nil {
			return nil, perr
		}
		req.Header.Set("DPoP", proof)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Learn before the status check, the rejection carries the nonce the retry needs.
	if c.dpop != nil {
		c.dpop.LearnHeaders(resp.Header)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDeviceResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return data, fmt.Errorf(
			"device authorization: HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(data)),
		)
	}
	return data, nil
}
