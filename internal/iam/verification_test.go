package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestPasswordLoginRequiresVerifiedEmail(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	svc := newSSOTestService(t, store, &fakeStoreConn{})

	u, err := svc.q.CreateUser(ctx, &db.CreateUserParams{Email: "user@test.dev", Name: "User"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := svc.Password.Store(ctx, u.ID, "correct horse battery"); err != nil {
		t.Fatalf("store password: %v", err)
	}

	if _, _, err := svc.Password.Login(
		ctx,
		"user@test.dev",
		"correct horse battery",
	); !errors.Is(
		err,
		ErrEmailUnverified,
	) {
		t.Fatalf("unverified login err = %v, want ErrEmailUnverified", err)
	}
	if err := svc.VerifyUserEmail(ctx, u.ID); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if _, _, err := svc.Password.Login(ctx, "user@test.dev", "correct horse battery"); err != nil {
		t.Fatalf("verified login: %v", err)
	}
}

func TestBackupCodeLoginRequiresVerifiedEmail(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	svc := newSSOTestService(t, store, &fakeStoreConn{})

	if _, err := svc.q.CreateUser(
		ctx,
		&db.CreateUserParams{Email: "user@test.dev", Name: "User"},
	); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// fakeStore does not implement ConsumeCredentialBySubject, so a call
	// past the gate would panic: a rejected login must not burn a code.
	_, _, err := svc.LoginWithBackupCode(ctx, "user@test.dev", "AAAAAAAAAAAA")
	if !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("err = %v, want ErrEmailUnverified", err)
	}
}

func TestHasRecentToken(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	svc := newSSOTestService(t, store, &fakeStoreConn{})

	u, err := svc.q.CreateUser(ctx, &db.CreateUserParams{Email: "user@test.dev", Name: "User"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	other, err := svc.q.CreateUser(
		ctx,
		&db.CreateUserParams{Email: "other@test.dev", Name: "Other"},
	)
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if _, err := svc.IssueToken(ctx, u.ID, TokenVerifyEmail, time.Hour); err != nil {
		t.Fatalf("issue token: %v", err)
	}

	cases := []struct {
		name    string
		userID  string
		purpose string
		want    bool
	}{
		{"same user and purpose", u.ID, TokenVerifyEmail, true},
		{"other user", other.ID, TokenVerifyEmail, false},
		{"other purpose", u.ID, TokenPasswordReset, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.HasRecentToken(ctx, tc.userID, tc.purpose)
			if err != nil {
				t.Fatalf("HasRecentToken: %v", err)
			}
			if got != tc.want {
				t.Errorf("HasRecentToken = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLinkerEmailVerificationPolicy(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	conn := &fakeStoreConn{}
	svc := newSSOTestService(t, store, conn)
	l := &linker{svc: svc, credType: MethodOIDC}
	now := time.Now()

	// A custom workspace provider without a domain binding rejects an
	// unverified claim (the pre-existing rule).
	_, err := l.Resolve(ctx, "ws1", flowLinkOptions{
		ProviderID:      "ws1",
		Subject:         "s1",
		Email:           "someone@unbound.test",
		JITProvisioning: true,
	})
	if !errors.Is(err, ErrIdentityRejected) {
		t.Fatalf("custom unbound unverified: err = %v, want ErrIdentityRejected", err)
	}

	// The same provider with a verified domain binding vouches for its
	// members even without the claim.
	conn.domains = append(conn.domains, &db.WorkspaceDomain{
		WorkspaceID: "ws1",
		Domain:      "unbound.test",
		ProviderID:  "ws1",
		VerifiedAt:  &now,
	})
	if _, err := l.Resolve(ctx, "ws1", flowLinkOptions{
		ProviderID:      "ws1",
		Subject:         "s2",
		Email:           "member@unbound.test",
		JITProvisioning: true,
	}); err != nil {
		t.Fatalf("custom bound unverified: %v", err)
	}

	// A public provider must assert the claim even when a workspace bound
	// the domain to it.
	conn.domains = append(conn.domains, &db.WorkspaceDomain{
		WorkspaceID: "ws1",
		Domain:      "gmail.com",
		ProviderID:  "google",
		VerifiedAt:  &now,
	})
	_, err = l.Resolve(ctx, "ws1", flowLinkOptions{
		ProviderID:      "google",
		Subject:         "s3",
		Email:           "claimant@gmail.com",
		Public:          true,
		JITProvisioning: true,
	})
	if !errors.Is(err, ErrIdentityRejected) {
		t.Fatalf("public unverified with binding: err = %v, want ErrIdentityRejected", err)
	}

	// A public provider with the verified claim provisions normally.
	u, err := l.Resolve(ctx, "", flowLinkOptions{
		ProviderID:      "google",
		Subject:         "s4",
		Email:           "real@gmail.com",
		EmailVerified:   true,
		Public:          true,
		JITProvisioning: true,
	})
	if err != nil {
		t.Fatalf("public verified: %v", err)
	}
	if !u.EmailVerified {
		t.Error("provisioned user should inherit the verified claim")
	}
}
