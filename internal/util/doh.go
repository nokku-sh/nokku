package util

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dohResponse is the subset of a DNS-over-HTTPS JSON response we need.
// See https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/
type dohResponse struct {
	Status int `json:"Status"` // 0 = NOERROR
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// LookupTXTDOH resolves the TXT records for name against a DNS-over-HTTPS
// JSON endpoint. Unlike the OS resolver, this bypasses local DNS caches
// (systemd-resolved, home routers) and always reflects the resolver's
// current view, which avoids negative-cache delays during domain
// verification. The returned values are unquoted.
func LookupTXTDOH(ctx context.Context, name, endpoint string) ([]string, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", "TXT")

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint+"?"+q.Encode(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build doh request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}

	var r dohResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode doh response: %w", err)
	}
	if r.Status != 0 {
		return nil, fmt.Errorf("doh dns status %d", r.Status)
	}

	records := make([]string, 0, len(r.Answer))
	for _, a := range r.Answer {
		records = append(records, strings.Trim(a.Data, `"`))
	}
	return records, nil
}
