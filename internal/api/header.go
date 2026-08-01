package api

import (
	"context"
	"encoding/json"
	"strings"

	"connectrpc.com/connect"
)

func getHeader(ctx context.Context, key string) string {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return ""
	}
	header := ci.RequestHeader().Get(key)
	return strings.ToLower(strings.TrimSpace(header))
}

func daemonMetadata(ctx context.Context) []byte {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil
	}
	h := ci.RequestHeader()
	metadata, _ := json.Marshal(map[string]string{
		"user-agent":  h.Get("User-Agent"),
		"host":        h.Get("Host"),
		"version":     h.Get("Nokku-Daemon-Version"),
		"fingerprint": h.Get("Nokku-Daemon-Fingerprint"),
	})
	return metadata
}
