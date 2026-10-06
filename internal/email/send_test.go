package email

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/cache"
)

type mockSender struct {
	sent  []message
	calls int
	err   error
}

func (m *mockSender) Send(_ context.Context, msg message) error {
	m.calls++
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func newTestService(sender sender) *Service {
	return &Service{
		sender:   sender,
		cache:    cache.NewMemory(0),
		From:     "noreply@system.nokku.sh",
		Cooldown: time.Hour,
	}
}

func TestSendTemplate_CallsSender(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)

	err := svc.SendWelcomeEmail(
		context.Background(),
		"user-1",
		"ada@example.com",
		"Ada",
		"https://app.nokku.sh/verify/token",
		"15 minutes",
	)
	if err != nil {
		t.Fatalf("SendWelcomeEmail: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("sender called %d times, want 1", len(sender.sent))
	}
	msg := sender.sent[0]
	if msg.From != "Nokku <noreply@system.nokku.sh>" {
		t.Errorf("From = %q", msg.From)
	}
	if msg.To != "ada@example.com" {
		t.Errorf("To = %q, want ada@example.com", msg.To)
	}
	if msg.Subject != "Welcome to Nokku" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.HTML, "Ada") {
		t.Error("HTML body missing rendered username")
	}
}

func TestSendTemplate_Cooldown(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := context.Background()

	if err := svc.SendVerificationEmail(ctx, "user-1", "a@b.io", "url", "10m"); err != nil {
		t.Fatalf("first send: %v", err)
	}

	err := svc.SendVerificationEmail(ctx, "user-1", "a@b.io", "url", "10m")
	if !errors.Is(err, errCooldown) {
		t.Fatalf("second send = %v, want errCooldown", err)
	}
	if len(sender.sent) != 1 {
		t.Errorf("sender called %d times, want 1", len(sender.sent))
	}
}

func TestSendTemplate_CooldownPerTemplate(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := context.Background()

	// Different templates for the same user must not share a cooldown key.
	if err := svc.SendWelcomeEmail(ctx, "user-1", "a@b.io", "Ada", "u", "10m"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "d1", "Chrome", "Vienna"); err != nil {
		t.Fatalf("different template blocked by cooldown: %v", err)
	}
	// Same template again is still blocked.
	if err := svc.SendWelcomeEmail(
		ctx,
		"user-1",
		"a@b.io",
		"Ada",
		"u",
		"10m",
	); !errors.Is(
		err,
		errCooldown,
	) {
		t.Errorf("repeat of same template = %v, want errCooldown", err)
	}
	if len(sender.sent) != 2 {
		t.Errorf("sender called %d times, want 2", len(sender.sent))
	}
}

func TestSendTemplate_CooldownPerUser(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := context.Background()

	if err := svc.SendRecoveryEmail(ctx, "user-1", "a@b.io", "u", "10m"); err != nil {
		t.Fatal(err)
	}
	// A different user must not be blocked by user-1's cooldown.
	if err := svc.SendRecoveryEmail(ctx, "user-2", "b@b.io", "u", "10m"); err != nil {
		t.Fatalf("other user blocked by cooldown: %v", err)
	}
}

func TestSendTemplate_SendErrorPropagatesWithoutCooldown(t *testing.T) {
	sender := &mockSender{err: errors.New("smtp down")}
	svc := newTestService(sender)
	ctx := context.Background()

	err := svc.SendVerificationEmail(ctx, "user-1", "a@b.io", "u", "10m")
	if err == nil || !strings.Contains(err.Error(), "smtp down") {
		t.Fatalf("error = %v, want smtp down", err)
	}

	// Failed sends must not set the cooldown, so a retry is possible.
	err = svc.SendVerificationEmail(ctx, "user-1", "a@b.io", "u", "10m")
	if errors.Is(err, errCooldown) {
		t.Fatal("failed send set cooldown, retry impossible")
	}
	if sender.calls != 2 {
		t.Errorf("sender called %d times, want 2", sender.calls)
	}
}

// A cooldown store someone filled must not hold back a reset or an alert.
func TestSendTemplate_FullCooldownStoreSendsAnyway(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	svc.cache = cache.NewMemory(1)
	if _, err := svc.cache.SetNX(context.Background(), "taken", nil, time.Hour); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := svc.SendRecoveryEmail(
			context.Background(), "user-1", "ada@example.com", "https://app.nokku.sh/reset/token", "15 minutes",
		); err != nil {
			t.Fatalf("SendRecoveryEmail with a full cooldown store: %v", err)
		}
	}
	if len(sender.sent) != 2 {
		t.Fatalf("sender called %d times, want 2", len(sender.sent))
	}
}

func TestSendTemplate_MissingUserID(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.SendVerificationEmail(context.Background(), "", "a@b.io", "u", "10m")
	if err == nil {
		t.Fatal("missing user id: want error")
	}
}

func TestSendTemplate_UnknownTemplate(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.sendTemplate(context.Background(), sendRequest{
		userID:   "user-1",
		to:       "a@b.io",
		subject:  "x",
		template: "does-not-exist",
	})
	if err == nil {
		t.Fatal("unknown template: want error")
	}
}

func TestSendTemplate_MessageAndData(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	svc.appURL = "https://app.nokku.sh"

	err := svc.SendNewLoginEmail(
		context.Background(),
		"user-1",
		"ada@example.com",
		"device-42",
		"Web browser",
		"203.0.113.7",
	)
	if err != nil {
		t.Fatal(err)
	}
	msg := sender.sent[0]
	if !strings.Contains(msg.HTML, "203.0.113.7") {
		t.Error("body missing IP address")
	}
	if !strings.Contains(msg.HTML, "device-42") {
		t.Error("body missing device id")
	}
	if !strings.Contains(msg.HTML, "https://app.nokku.sh/profile/security") {
		t.Error("body missing profile URL")
	}
}

// Concurrent sends for the same user and template must deliver exactly once.
func TestSendTemplate_ConcurrentSendsOnce(t *testing.T) {
	sender := &countingSender{}
	svc := newTestService(sender)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_ = svc.SendVerificationEmail(t.Context(), "user-1", "a@b.io", "u", "10m")
		})
	}
	wg.Wait()
	if n := sender.n.Load(); n != 1 {
		t.Errorf("sent %d times, want 1", n)
	}
}

type countingSender struct{ n atomic.Int32 }

func (c *countingSender) Send(context.Context, message) error {
	c.n.Add(1)
	return nil
}
