package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/cli/internal/state"
	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const (
	// Past the core's 10s limit, or a spent job token could lose its session.
	exchangeTimeout     = 15 * time.Second
	jobTokenTimeout     = 10 * time.Second
	maxJobTokenResponse = 64 << 10
)

// ErrCISessionEnded stops a job, a browser sign-in would wait on nobody.
var ErrCISessionEnded = errors.New("the CI session ended, run nk login --ci <service account> again. " +
	"To sign in as a person instead, run nk logout first")

func (c *Client) LoginCI(ctx context.Context, account string) error {
	if account == "" {
		return errors.New("nk login --ci needs the name of a service account")
	}
	if c.State.IsServiceAccount() {
		return errors.New("NK_TOKEN is set, unset it to sign in with the job's token")
	}
	token, err := jobToken(ctx, strings.TrimRight(c.State.APIURL, "/"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	res, err := c.auth.ExchangeWorkloadToken(ctx, &nokkuv1.ExchangeWorkloadTokenRequest{
		ServiceAccount: &account,
		Token:          &token,
	})
	if err != nil {
		return fmt.Errorf("sign in as %s: %w", account, err)
	}
	c.State.SessionToken = res.GetAccessToken()
	c.State.SessionExpiresAt = res.GetExpiresAt().AsTime()
	// A job whose first sync fails must still never reach the device flow.
	c.State.Cache = state.Cache{Server: c.State.APIURL, ServiceAccount: &state.ServiceAccount{Name: account}}
	return c.State.Save()
}

func jobToken(ctx context.Context, audience string) (string, error) {
	requestURL, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL != "" && bearer != "" {
		return githubJobToken(ctx, requestURL, bearer, audience)
	}
	if token := strings.TrimSpace(os.Getenv("NK_ID_TOKEN")); token != "" {
		return token, nil
	}
	return "", errors.New("no job token. On GitHub Actions give the job permissions: id-token: write. " +
		"On GitLab set NK_ID_TOKEN through id_tokens, with the address of the core as aud. " +
		"Anywhere else set NK_ID_TOKEN to the job's signed token")
}

func githubJobToken(ctx context.Context, requestURL, bearer, audience string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, jobTokenTimeout)
	defer cancel()
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	query := u.Query()
	query.Set("audience", audience)
	u.RawQuery = query.Encode()
	// #nosec G704 -- the runner names this URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+bearer)
	// #nosec G704 -- as above.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ask GitHub Actions for a job token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ask GitHub Actions for a job token: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJobTokenResponse))
	if err != nil {
		return "", fmt.Errorf("ask GitHub Actions for a job token: %w", err)
	}
	var answer struct {
		Value string `json:"value"`
	}
	if err = json.Unmarshal(data, &answer); err != nil || answer.Value == "" {
		return "", errors.New("ask GitHub Actions for a job token: the answer holds no token")
	}
	return answer.Value, nil
}
