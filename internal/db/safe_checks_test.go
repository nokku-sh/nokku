package db

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSafeTimestamp(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)

	if got := SafeTimestamp(nil); got != nil {
		t.Errorf("SafeTimestamp(nil) = %v, want nil", got)
	}

	got := SafeTimestamp(&now)
	if got == nil {
		t.Fatal("SafeTimestamp(non-nil) = nil")
	}
	if want := timestamppb.New(now); !got.AsTime().Equal(want.AsTime()) {
		t.Errorf("SafeTimestamp() = %v, want %v", got.AsTime(), want.AsTime())
	}
}
