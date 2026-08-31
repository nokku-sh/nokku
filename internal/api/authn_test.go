package api

import (
	"testing"
)

func TestRequestWorkspace(t *testing.T) {
	t.Run("nil request is safe for streaming RPCs", func(t *testing.T) {
		tenant := requestWorkspace(nil)
		if tenant != "" {
			t.Fatalf("requestWorkspace(nil) tenant = %q, want empty", tenant)
		}
	})
}
