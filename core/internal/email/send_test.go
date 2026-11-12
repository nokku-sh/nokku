package email

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
)

type mockSender struct {
	sent  []message
	calls int
	err   error
}

type countingSender struct{ n atomic.Int32 }

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
		cache:    cache.New[string, struct{}](cooldownEntries, cooldown),
		SMTPFrom: "noreply@system.nokku.sh",
	}
}

func TestSendTemplate_CallsSender(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)

	err := svc.SendInviteEmail(
		t.Context(),
		"ada@example.com",
		"Acme",
		"editor",
		"https://acme.nokku.sh/invite?token=secret",
		7*24*time.Hour,
	)
	require.NoError(t, err)

	require.Len(t, sender.sent, 1)
	msg := sender.sent[0]
	assert.Equal(t, "Nokku <noreply@system.nokku.sh>", msg.From)
	assert.Equal(t, "ada@example.com", msg.To)
	assert.Equal(t, "Join Acme on Nokku", msg.Subject)
	assert.Contains(t, msg.HTML, "editor", "HTML body missing rendered role")
}

func TestSendTemplate_Cooldown(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.NoError(t, svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "url", 10*time.Minute), "first send")

	err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "url", 10*time.Minute)
	require.ErrorIs(t, err, ErrCooldown, "second send")
	assert.Len(t, sender.sent, 1)
}

func TestSendTemplate_CooldownPerTemplate(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.NoError(t, svc.SendInviteEmail(ctx, "a@b.io", "Acme", "member", "u", 10*time.Minute))
	require.NoError(t, svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "d1", "Chrome", "Vienna"),
		"different template blocked by cooldown")
	err := svc.SendInviteEmail(ctx, "a@b.io", "Acme", "member", "u", 10*time.Minute)
	assert.Len(t, sender.sent, 2)
	assert.ErrorIs(t, err, ErrCooldown, "repeat of same template")
}

// Another workspace is not held back, and learns nothing of the first invite.
func TestSendInviteEmail_CooldownPerWorkspace(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	in := func(ws string) context.Context {
		return actor.WithWorkspace(t.Context(), actor.Workspace{ID: ws})
	}

	require.NoError(t, svc.SendInviteEmail(in("w1"), "a@b.io", "Acme", "member", "u", 10*time.Minute))
	require.NoError(t, svc.SendInviteEmail(in("w2"), "a@b.io", "Other", "member", "u", 10*time.Minute),
		"another workspace was held back")
	err := svc.SendInviteEmail(in("w1"), "a@b.io", "Acme", "member", "u", 10*time.Minute)
	assert.ErrorIs(t, err, ErrCooldown, "same workspace again")
}

// A sign-in link must not hold back an email change. A second change waits.
func TestSendEmailChangeConfirm_OwnCooldown(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.NoError(t, svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", 10*time.Minute))
	require.False(t, svc.EmailChangeOnCooldown("user-1"), "a sign-in link counts as an email change")
	require.NoError(t, svc.SendEmailChangeConfirm(ctx, "user-1", "new@b.io", "u", time.Hour),
		"confirmation blocked by the sign-in link")
	assert.True(t, svc.EmailChangeOnCooldown("user-1"), "no cooldown after a confirmation went out")
	err := svc.SendEmailChangeConfirm(ctx, "user-1", "new@b.io", "u", time.Hour)
	assert.Len(t, sender.sent, 2)
	assert.ErrorIs(t, err, ErrCooldown, "second confirmation")
}

// Each hosted signup is a new owner, so only the address holds back a mail.
func TestSendOwnerLinkEmail_CooldownPerAddress(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.False(t, svc.OwnerLinkOnCooldown("a@b.io"), "cooldown before any link went out")
	require.NoError(t, svc.SendOwnerLinkEmail(ctx, "a@b.io", "u", 24*time.Hour))
	assert.True(t, svc.OwnerLinkOnCooldown("a@b.io"), "no cooldown after the link went out")
	err := svc.SendOwnerLinkEmail(ctx, "a@b.io", "u", 24*time.Hour)
	assert.False(t, svc.OwnerLinkOnCooldown("c@b.io"), "another address shares the cooldown")
	assert.Len(t, sender.sent, 1)
	assert.ErrorIs(t, err, ErrCooldown, "second link to the address")
}

func TestSendTemplate_CooldownPerUser(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.NoError(t, svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", 10*time.Minute))
	require.NoError(t, svc.SendMagicLinkEmail(ctx, "user-2", "b@b.io", "u", 10*time.Minute),
		"other user blocked by cooldown")
}

func TestSendTemplate_SendErrorPropagatesWithoutCooldown(t *testing.T) {
	sender := &mockSender{err: errors.New("smtp down")}
	svc := newTestService(sender)
	ctx := t.Context()

	err := svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", 10*time.Minute)
	require.ErrorContains(t, err, "smtp down")

	err = svc.SendMagicLinkEmail(ctx, "user-1", "a@b.io", "u", 10*time.Minute)
	require.NotErrorIs(t, err, ErrCooldown, "failed send set cooldown, retry impossible")
	assert.Equal(t, 2, sender.calls)
}

// A cooldown store someone filled must not hold back a reset or an alert.
func TestSendTemplate_FullCooldownStoreSendsAnyway(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	svc.cache = cache.New[string, struct{}](1, cooldown)
	svc.cache.Set("taken", struct{}{})

	err := svc.SendMagicLinkEmail(
		t.Context(), "user-1", "ada@example.com", "https://acme.nokku.sh/reset/token", 15*time.Minute,
	)
	require.NoError(t, err)
	require.Len(t, sender.sent, 1)
}

func TestSendTemplate_MissingUserID(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.SendMagicLinkEmail(t.Context(), "", "a@b.io", "u", 10*time.Minute)
	require.Error(t, err, "missing user id")
}

func TestSendTemplate_UnknownTemplate(t *testing.T) {
	svc := newTestService(&mockSender{})

	err := svc.sendTemplate(t.Context(), sendRequest{
		userID:   "user-1",
		to:       "a@b.io",
		subject:  "x",
		template: "does-not-exist",
	})
	require.Error(t, err, "unknown template")
}

func TestSendTemplate_MessageAndData(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	svc.appURL = "https://acme.nokku.sh"

	err := svc.SendNewLoginEmail(
		t.Context(),
		"user-1",
		"ada@example.com",
		"device-42",
		"Web browser",
		"203.0.113.7",
	)
	require.NoError(t, err)
	msg := sender.sent[0]
	assert.Contains(t, msg.HTML, "203.0.113.7", "body missing IP address")
	assert.Contains(t, msg.HTML, "device-42", "body missing device id")
	assert.Contains(t, msg.HTML, "https://acme.nokku.sh/profile/security", "body missing profile URL")
	assert.Equal(t, "New sign-in from Web browser", msg.Subject)
	assert.Contains(t, msg.Text, "203.0.113.7", "text part missing the IP address")
	assert.Contains(t, msg.Text, "https://acme.nokku.sh/profile/security", "text part missing the profile URL")
}

// The text part is not html escaped, so a long query stays clickable.
func TestSendTemplate_TextPartKeepsURLs(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	link := "https://acme.nokku.sh/email-change?cancel=1&token=t"
	require.NoError(t, svc.SendEmailChangeNotice(t.Context(), "user-1", "a@b.io", "new@b.io", link, 7*24*time.Hour))
	msg := sender.sent[0]
	assert.Contains(t, msg.Text, link)
	assert.Contains(t, msg.HTML, "cancel=1&amp;token=t", "html part is not escaped")
}

// The mask keeps a whole letter, half of one is invalid UTF-8.
func TestEmailChangeNoticeMasksWholeLetters(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	require.NoError(t, svc.SendEmailChangeNotice(t.Context(), "user-1", "a@b.io", "éa@b.io", "https://x", time.Hour))
	assert.Contains(t, sender.sent[0].Text, "é***@b.io")
}

// Concurrent sends for the same user and template must deliver exactly once.
func TestSendTemplate_ConcurrentSendsOnce(t *testing.T) {
	sender := &countingSender{}
	svc := newTestService(sender)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_ = svc.SendMagicLinkEmail(t.Context(), "user-1", "a@b.io", "u", 10*time.Minute)
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, sender.n.Load())
}

func (c *countingSender) Send(context.Context, message) error {
	c.n.Add(1)
	return nil
}

func TestLifetime(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{15 * time.Minute, "15 minutes"},
		{time.Hour, "1 hour"},
		{90 * time.Minute, "90 minutes"},
		{24 * time.Hour, "24 hours"},
		{7 * 24 * time.Hour, "7 days"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, lifetime(tt.d))
	}
}

// A security mail never hides another: each device and way in gets its own.
func TestSecurityMailsCoolDownPerDeviceAndCredential(t *testing.T) {
	sender := &mockSender{}
	svc := newTestService(sender)
	ctx := t.Context()

	require.NoError(t, svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "browser", "Firefox", "ip"))
	require.NoError(t, svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "nk", "nk on laptop", "ip"))
	require.ErrorIs(t, svc.SendNewLoginEmail(ctx, "user-1", "a@b.io", "nk", "nk on laptop", "ip"), ErrCooldown)

	require.NoError(t, svc.SendNewWayInEmail(ctx, "user-1", "a@b.io", "passkey-1", "A passkey", "ip"))
	require.NoError(t, svc.SendNewWayInEmail(ctx, "user-1", "a@b.io", "google:sub", "Google", "ip"))
	require.ErrorIs(t, svc.SendNewWayInEmail(ctx, "user-1", "a@b.io", "passkey-1", "A passkey", "ip"), ErrCooldown)

	assert.Len(t, sender.sent, 4)
}
