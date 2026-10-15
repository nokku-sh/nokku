package iam

// Test sign-ins run the whole OIDC flow and stop before anyone is signed in, linked or created.

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/coreos/go-oidc/v3/oidc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	testEntries     = 1_000
	testTTL         = 10 * time.Minute
	ssoSettingsPath = "/settings/sso"
)

// errRollback ends a preview's tx, so the sign-in decision runs for real and leaves nothing behind.
var errRollback = errors.New("iam: preview rolls back")

// tester is the owner who started a test. Only they read the result.
type tester struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
}

// Test starts a test sign-in. It also takes a disabled provider, so it can be checked before anyone sees it.
func (h *oidcFlow) Test(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Only the settings page's own request, the Lax session cookie rides on any navigation.
	p, ok := actor.PrincipalFromContext(ctx)
	if !ok || p.Kind != actor.KindUser || p.Role != nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER ||
		r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		fail(w, r, "test refused")
		return
	}
	t := &tester{UserID: p.ID, Email: p.Email}
	cfg, err := h.svc.GetSSOProvider(ctx, r.URL.Query().Get("provider"))
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}
	provider, err := h.discover(ctx, cfg.OIDC.IssuerURL)
	if err != nil {
		h.finishTest(w, r, t, failedTest(cfg, nokkuv1.SSOTestStep_SSO_TEST_STEP_DISCOVERY, err))
		return
	}
	h.start(w, r, cfg, provider, authorizeState{Tester: t})
}

// finishTestFlow is the callback of a test. It checks what a sign-in checks, then only reports.
func (h *oidcFlow) finishTestFlow(w http.ResponseWriter, r *http.Request, flowID string, st authorizeState) {
	ctx := r.Context()
	h.svc.spendFlow(ctx, flowID)
	http.SetCookie(w, h.svc.newCookie(flowCookieName, "", time.Unix(0, 0)))
	cfg, err := h.svc.GetSSOProvider(ctx, st.ProviderID)
	if err != nil {
		fail(w, r, "provider not configured")
		return
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		err := errors.New(strings.TrimSuffix(e+": "+q.Get("error_description"), ": "))
		h.finishTest(w, r, st.Tester, failedTest(cfg, nokkuv1.SSOTestStep_SSO_TEST_STEP_AUTHORIZE, err))
		return
	}
	idToken, claims, step, err := h.verify(ctx, q, cfg, st)
	if err != nil {
		h.finishTest(w, r, st.Tester, failedTest(cfg, step, err))
		return
	}

	id := identityFrom(cfg, idToken, claims)
	res := &nokkuv1.SSOTest{
		ProviderId:    &cfg.ProviderID,
		Subject:       &id.Subject,
		Email:         &id.Email,
		Name:          &id.Name,
		EmailVerified: new(!id.EmailUnverified),
		Claims:        slices.Sorted(maps.Keys(claims)),
	}
	outcome, member, err := h.preview(ctx, id)
	if err != nil {
		// The provider checks out either way, so the result still shows.
		slog.Warn("sso test preview failed", "error", err, "provider", cfg.ProviderID)
	} else {
		res.Outcome, res.MemberEmail = outcome.Enum(), &member
	}
	h.finishTest(w, r, st.Tester, res)
}

// preview runs resolve's decision in a tx it rolls back, so it never drifts from what a sign-in does.
func (h *oidcFlow) preview(ctx context.Context, id oidcIdentity) (nokkuv1.SSOTestOutcome, string, error) {
	var u *db.User
	created := false
	err := h.svc.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if u, created, err = h.resolveIn(ctx, q, id); err != nil {
			return err
		}
		return errRollback
	})
	switch {
	case errors.Is(err, errRollback) && created:
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_CREATES, "", nil
	case errors.Is(err, errRollback) && !u.Active:
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_INACTIVE, u.Email, nil
	case errors.Is(err, errRollback):
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_SIGNS_IN, u.Email, nil
	case errors.Is(err, errIdentityRejected) && id.Email == "":
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_NO_EMAIL, "", nil
	case errors.Is(err, errIdentityRejected):
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_NO_ACCOUNT, "", nil
	case errors.Is(err, errEmailUnverified):
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_EMAIL_UNVERIFIED, "", nil
	case errors.Is(err, errOwnerLink):
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_OWNER_LINK, normalizeEmail(id.Email), nil
	case errors.Is(err, ErrSeatLimit):
		return nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_NO_SEAT, "", nil
	}
	return 0, "", err
}

func failedTest(cfg *SSOProvider, step nokkuv1.SSOTestStep, err error) *nokkuv1.SSOTest {
	return &nokkuv1.SSOTest{ProviderId: &cfg.ProviderID, FailedStep: step.Enum(), Error: new(err.Error())}
}

// finishTest keeps the result for its tester and sends them back to the settings page.
func (h *oidcFlow) finishTest(w http.ResponseWriter, r *http.Request, t *tester, res *nokkuv1.SSOTest) {
	ctx := r.Context()
	res.TestedAt = timestamppb.New(h.svc.now())
	detail := res.GetProviderId() + " passed"
	if res.FailedStep != nil {
		detail = res.GetProviderId() + " failed: " + res.GetError()
	}
	h.svc.record(ctx, event{
		Action: actionSSOTested,
		Kind:   actor.KindUser,
		Method: MethodOIDC,
		UserID: t.UserID,
		Email:  t.Email,
		Detail: detail,
	})

	id := crypto.RandomString(32)
	raw, err := proto.Marshal(res)
	if err == nil {
		err = h.tests.Set(ctx, testKey(ctx, t.UserID, id), raw, testTTL)
	}
	if err != nil {
		slog.Warn("sso test result not kept", "error", err)
		fail(w, r, "test result lost")
		return
	}
	http.Redirect(w, r, ssoSettingsPath+"?test="+url.QueryEscape(id), http.StatusSeeOther)
}

func testKey(ctx context.Context, userID, id string) string {
	return actor.WorkspaceIDFromContext(ctx) + ":" + userID + ":" + id
}

// SSOTest returns a test result to the owner who ran it.
func (s *Service) SSOTest(ctx context.Context, id string) (*nokkuv1.SSOTest, error) {
	raw, err := s.OIDC.tests.Get(ctx, testKey(ctx, actor.UserIDFromContext(ctx), id))
	if err != nil {
		return nil, ErrNotFound
	}
	res := &nokkuv1.SSOTest{}
	if err := proto.Unmarshal(raw, res); err != nil {
		return nil, err
	}
	return res, nil
}

// CheckIssuer loads the issuer's discovery document, so a typo fails on save and not at the first sign-in.
// It skips the discovery cache, an issuer that is typed but never saved must not stay in it.
func (s *Service) CheckIssuer(ctx context.Context, issuer string) error {
	_, err := oidc.NewProvider(s.providerContext(ctx), issuer)
	return err
}
