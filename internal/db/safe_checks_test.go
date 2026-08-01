package db

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
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

func TestSafeDuration(t *testing.T) {
	d := 90 * time.Hour

	if got := SafeDuration(nil); got != nil {
		t.Errorf("SafeDuration(nil) = %v, want nil", got)
	}

	got := SafeDuration(&d)
	if got == nil {
		t.Fatal("SafeDuration(non-nil) = nil")
	}
	if want := durationpb.New(d); got.AsDuration() != want.AsDuration() {
		t.Errorf("SafeDuration() = %v, want %v", got.AsDuration(), want.AsDuration())
	}
}
