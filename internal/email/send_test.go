package email

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mizuchilabs/kagi"
)

type mockSender struct {
	sent  []Message
	calls int
	err   error
}

func (m *mockSender) Send(_ context.Context, msg Message) error {
	m.calls++
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func newTestService(sender Sender) *Service {
	return &Service{
		sender:   sender,
		cache:    kagi.NewMemoryCache(0),
		Sender:   "noreply@system.nokku.sh",
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
	if msg.From.Email != "noreply@system.nokku.sh" {
		t.Errorf("From = %+v, want noreply@system.nokku.sh", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0].Email != "ada@example.com" {
		t.Errorf("To = %+v, want ada@example.com", msg.To)
	}
	if msg.Subject != "Welcome to Nokku" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.HTMLBody, "Ada") {
		t.Error("HTML body missing rendered username")
	}
	if msg.Tags["template"] != "welcome" || msg.Headers["X-Nokku-Template"] != "welcome" {
		t.Errorf("Tags = %v, Headers = %v", msg.Tags, msg.Headers)
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
		ErrCooldown,
	) {
		t.Errorf("repeat of same template = %v, want ErrCooldown", err)
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
	if errors.Is(err, ErrCooldown) {
		t.Fatal("failed send set cooldown, retry impossible")
	}
	if sender.calls != 2 {
		t.Errorf("sender called %d times, want 2", sender.calls)
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
		to:       Address{Email: "a@b.io"},
		subject:  "x",
		template: "does-not-exist",
	})
	if err == nil {
		t.Fatal("unknown template: want error")
	}
}

func TestSendTemplate_NilService(t *testing.T) {
	var svc *Service
	if err := svc.SendWelcomeEmail(
		context.Background(),
		"user-1",
		"a@b.io",
		"Ada",
		"u",
		"10m",
	); err != nil {
		t.Errorf("nil service: %v, want nil", err)
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
		"Innsbruck, Austria",
	)
	if err != nil {
		t.Fatal(err)
	}
	msg := sender.sent[0]
	if !strings.Contains(msg.HTMLBody, "device-42") {
		t.Error("body missing device id")
	}
	if !strings.Contains(msg.HTMLBody, "https://app.nokku.sh/profile/security") {
		t.Error("body missing profile URL")
	}
}
