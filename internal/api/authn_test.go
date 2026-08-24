package api

import (
	"testing"
)

func TestRequestWorkspace(t *testing.T) {
	t.Run("nil message is safe for streaming RPCs", func(t *testing.T) {
		tenant, err := requestWorkspace(nil)
		if err != nil {
			t.Fatalf("requestWorkspace(nil) error: %v", err)
		}
		if tenant != "" {
			t.Fatalf("requestWorkspace(nil) tenant = %q, want empty", tenant)
		}
	})
}
