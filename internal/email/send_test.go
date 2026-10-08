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

	err := svc.SendSignupLinkEmail(
		t.Context(),
		"ada@example.com",
		"Ada",
		"Acme",
		"https://acme.nokku.sh/invite/verify?token=secret",
		"15 minutes",
	)
	if err != nil {
		t.Fatalf("SendSignupLinkEmail: %v", err)
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
	if msg.Subject != "Join Acme on Nokku" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.HTML, "Ada") {
		t.Error("HTML body missing rendered username")
	}
}

func TestSendTemplate_Cooldown(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	if err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "url", "10m"); err != nil {
		t.Fatalf("first send: %v", err)
	}

	err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "url", "10m")
	if !errors.Is(err, ErrCooldown) {
		t.Fatalf("second send = %v, want ErrCooldown", err)
	}
	if len(sender.sent) != 1 {
		t.Errorf("sender called %d times, want 1", len(sender.sent))
	}
}

func TestSendTemplate_CooldownPerTemplate(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	// Different templates for the same user must not share a cooldown key.
	if err := svc.SendSignupLinkEmail(ctx, "a@b.io", "Ada", "Acme", "u", "10m"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "d1", "Chrome", "Vienna"); err != nil {
		t.Fatalf("different template blocked by cooldown: %v", err)
	}
	// Same template again is still blocked.
	if err := svc.SendSignupLinkEmail(
		ctx,
		"a@b.io",
		"Ada",
		"Acme",
		"u",
		"10m",
	); !errors.Is(
		err,
		ErrCooldown,
	) {
		t.Errorf("repeat of same template = %v, want ErrCooldown", err)
	}
	if len(sender.sent) != 2 {
		t.Errorf("sender called %d times, want 2", len(sender.sent))
	}
}

// A sign-in link a moment ago must not hold back an email change. A second
// change still waits, and the caller can ask before it starts one.
func TestSendEmailChangeConfirm_OwnCooldown(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	if err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", "10m"); err != nil {
		t.Fatal(err)
	}
	if svc.EmailChangeOnCooldown(ctx, "user-1") {
		t.Fatal("a sign-in link counts as an email change")
	}
	if err := svc.SendEmailChangeConfirm(ctx, "user-1", "new@b.io", "u", "1h"); err != nil {
		t.Fatalf("confirmation blocked by the sign-in link: %v", err)
	}
	if !svc.EmailChangeOnCooldown(ctx, "user-1") {
		t.Error("no cooldown after a confirmation went out")
	}
	if err := svc.SendEmailChangeConfirm(ctx, "user-1", "new@b.io", "u", "1h"); !errors.Is(err, ErrCooldown) {
		t.Errorf("second confirmation = %v, want ErrCooldown", err)
	}
	if len(sender.sent) != 2 {
		t.Errorf("sender called %d times, want 2", len(sender.sent))
	}
}

// Every hosted signup makes a new owner, so only the address can hold back a
// second mail. The caller can ask before it makes the workspace.
func TestSendOwnerLinkEmail_CooldownPerAddress(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	if svc.OwnerLinkOnCooldown(ctx, "a@b.io") {
		t.Fatal("cooldown before any link went out")
	}
	if err := svc.SendOwnerLinkEmail(ctx, "a@b.io", "u", "24h"); err != nil {
		t.Fatal(err)
	}
	if !svc.OwnerLinkOnCooldown(ctx, "a@b.io") {
		t.Error("no cooldown after the link went out")
	}
	if err := svc.SendOwnerLinkEmail(ctx, "a@b.io", "u", "24h"); !errors.Is(err, ErrCooldown) {
		t.Errorf("second link to the address = %v, want ErrCooldown", err)
	}
	if svc.OwnerLinkOnCooldown(ctx, "c@b.io") {
		t.Error("another address shares the cooldown")
	}
	if len(sender.sent) != 1 {
		t.Errorf("sender called %d times, want 1", len(sender.sent))
	}
}

func TestSendTemplate_CooldownPerUser(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	if err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", "10m"); err != nil {
		t.Fatal(err)
	}
	// A different user must not be blocked by user-1's cooldown.
	if err := svc.SendMagicLinkEmail(ctx, "user-2", "b@b.io", "u", "10m"); err != nil {
		t.Fatalf("other user blocked by cooldown: %v", err)
	}
}

func TestSendTemplate_SendErrorPropagatesWithoutCooldown(t *testing.T) {
	sender := &mockSender{err: errors.New("smtp down")}
	svc := newTestService(sender)
	ctx := t.Context()

	err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", "10m")
	if err == nil || !strings.Contains(err.Error(), "smtp down") {
		t.Fatalf("error = %v, want smtp down", err)
	}

	// Failed sends must not set the cooldown, so a retry is possible.
	err = svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", "10m")
	if errors.Is(err, ErrCooldown) {
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
	if _, err := svc.cache.SetNX(t.Context(), "taken", nil, time.Hour); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if err := svc.SendMagicLinkEmail(
			t.Context(), "user-1", "ada@example.com", "https://app.nokku.sh/reset/token", "15 minutes",
		); err != nil {
			t.Fatalf("SendMagicLinkEmail with a full cooldown store: %v", err)
		}
	}
	if len(sender.sent) != 2 {
		t.Fatalf("sender called %d times, want 2", len(sender.sent))
	}
}

func TestSendTemplate_MissingUserID(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.SendMagicLinkEmail(t.Context(), "", "a@b.io", "u", "10m")
	if err == nil {
		t.Fatal("missing user id: want error")
	}
}

func TestSendTemplate_UnknownTemplate(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.sendTemplate(t.Context(), sendRequest{
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
		t.Context(),
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
			_ = svc.SendMagicLinkEmail(t.Context(), "user-1", "a@b.io", "u", "10m")
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
