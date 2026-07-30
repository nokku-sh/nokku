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

// daemonMetadata builds the metadata JSON blob from daemon request headers.
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

// // cliMetadata builds the metadata JSON blob from client request headers.
// func cliMetadata(ctx context.Context) []byte {
// 	ci, ok := connect.CallInfoForHandlerContext(ctx)
// 	if !ok {
// 		return nil
// 	}
// 	h := ci.RequestHeader()
// 	metadata, _ := json.Marshal(map[string]string{
// 		"user-agent":  h.Get("user-agent"),
// 		"host":        h.Get("host"),
// 		"version":     h.Get("nokku-client-version"),
// 		"fingerprint": h.Get("nokku-client-fingerprint"),
// 	})
// 	return metadata
// }
