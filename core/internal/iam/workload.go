package iam

// A CI job proves who it is with a token its platform signed, and trades it for a short session of a service account.
// The core is the relying party, as for SSO. What may sign in is decided by rules an admin stored, never by the token.

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	workloadSessionTTL = time.Hour
	workloadSkew       = time.Minute
	// workloadMaxAge stays under the session by the skew. A session row can end before an iat a minute ahead turns an
	// hour old, and a job token must not work again in that gap.
	workloadMaxAge = workloadSessionTTL - workloadSkew
	// A unique index takes a little over 2 KiB per row. No platform comes near this.
	maxWorkloadJTI = 256
	// maxRefusalReason bounds what a refused exchange writes, a provider's error can quote a whole answer.
	maxRefusalReason = 256

	githubActionsHost = "token.actions.githubusercontent.com"
	gitlabHost        = "gitlab.com"
)

// checkedClaims are what the core checks on every job token itself, a rule has no say in them.
var checkedClaims = []string{"aud", "iss", "exp", "iat", "nbf", "jti"}

// Workload is a job token that passed every check.
type Workload struct {
	Account *db.ServiceAccount
	Rule    *db.ServiceAccountFederation
	Subject string
	JTI     string
	Expiry  time.Time
}

// WorkloadRefusedError says why an exchange was turned down, for the audit log and the log. The caller answers one
// generic error for every refusal.
type WorkloadRefusedError struct {
	Account *db.ServiceAccount // nil when the name found none
	Reason  string
	// Signed says the issuer of a stored rule vouched for the token. Anyone can send one that isn't, at the rate limit.
	Signed bool
}

func (r *WorkloadRefusedError) Error() string { return "iam: workload token refused: " + r.Reason }

// ValidateFederation checks a rule before it is stored. Its errors are for the admin who wrote it.
func ValidateFederation(issuer string, claims map[string]string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.User != nil || strings.ContainsFunc(issuer, unicode.IsSpace) {
		return errors.New("the issuer must be an https URL with no query, a job token names it exactly")
	}
	if len(claims) == 0 {
		return errors.New("a rule needs at least one claim, without one every job of the issuer would sign in")
	}
	for _, name := range slices.Sorted(maps.Keys(claims)) {
		if name == "" {
			return errors.New("a claim needs a name")
		}
		if slices.Contains(checkedClaims, name) {
			return fmt.Errorf("the claim %s can't be matched on, the core checks it on every job token itself", name)
		}
		if strings.TrimSpace(claims[name]) == "" {
			return fmt.Errorf("the claim %s needs a value, it is compared exactly", name)
		}
	}
	has := func(name string) bool { return claims[name] != "" }
	switch strings.ToLower(u.Hostname()) {
	case githubActionsHost:
		if !has("repository_id") || (!has("environment") && !has("ref")) {
			return errors.New(
				"a GitHub Actions rule needs repository_id plus environment or ref. repository_id alone " +
					"covers every branch and pull request, and a repository name can be registered again by someone else",
			)
		}
	case gitlabHost:
		if !has("project_id") || (!has("environment") && !has("ref_path") && (!has("ref") || !has("ref_type"))) {
			return errors.New("a GitLab rule needs project_id plus environment, ref_path, or ref with ref_type. " +
				"project_id alone covers every branch and merge request, a ref alone also matches a tag of that name, " +
				"and a project path can be registered again by someone else")
		}
	default:
		if !has("sub") {
			return errors.New("a rule for this issuer needs sub, it is what names the job")
		}
	}
	return nil
}

// VerifyWorkload runs every check of an exchange on raw, in this order. A *WorkloadRefusedError is the answer about the
// job, any other error means the check could not run.
func (s *Service) VerifyWorkload(ctx context.Context, name, raw string) (*Workload, error) {
	account, err := s.conn.Tenant().GetServiceAccountByName(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &WorkloadRefusedError{Reason: "no service account has this name"}
	}
	if err != nil {
		return nil, err
	}
	refusal := func(signed bool, format string, args ...any) error {
		reason := strings.ReplaceAll(fmt.Sprintf(format, args...), "\x00", "")
		return &WorkloadRefusedError{Account: account, Reason: truncate(reason, maxRefusalReason), Signed: signed}
	}
	reject := func(format string, args ...any) (*Workload, error) { return nil, refusal(false, format, args...) }
	deny := func(format string, args ...any) (*Workload, error) { return nil, refusal(true, format, args...) }
	rules, err := s.conn.Tenant().ListServiceAccountFederations(ctx, account.ID)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return reject("the account has no rules")
	}
	// Only picks rules. Everything after this trusts the issuer of a stored rule, so a job can't name its own.
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return reject("the token is no JWT with an issuer")
	}
	rules = slices.DeleteFunc(rules, func(r *db.ServiceAccountFederation) bool { return r.Issuer != iss })
	if len(rules) == 0 {
		return reject("no rule names the issuer %q", iss)
	}
	issuer := rules[0].Issuer

	provider, err := s.OIDC.discover(ctx, issuer)
	if err != nil {
		return reject("the issuer did not answer: %v", err)
	}
	// The audience is checked below, so a job with the wrong one still leaves a row. go-oidc checks the signature first.
	verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true, Now: s.now})
	token, err := verifier.Verify(s.providerContext(ctx), raw)
	if _, expired := errors.AsType[*oidc.TokenExpiredError](err); expired {
		return deny("the token has expired")
	}
	if err != nil {
		return reject("%v", err)
	}
	if want := baseURL(ctx); !slices.Contains(token.Audience, want) {
		return deny("expected audience %q, the token has %q", want, token.Audience)
	}

	now := s.now()
	switch {
	case !token.Expiry.After(now):
		return deny("the token has expired")
	case token.IssuedAt.IsZero():
		return deny("the token has no iat")
	case now.Sub(token.IssuedAt) > workloadMaxAge:
		return deny("the token is too old, its iat is %s", token.IssuedAt.UTC().Format(time.RFC3339))
	case token.IssuedAt.Sub(now) > workloadSkew:
		return deny("the iat of the token is in the future")
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return deny("the claims can't be read: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || len(jti) > maxWorkloadJTI {
		return deny("the token has no usable jti")
	}
	// Both are stored, and Postgres takes no NUL.
	if strings.ContainsRune(jti+token.Subject, 0) {
		return deny("the token has a NUL in its jti or sub")
	}
	i := slices.IndexFunc(rules, func(r *db.ServiceAccountFederation) bool { return ruleMatches(r.Claims, claims) })
	if i < 0 {
		return deny("no rule of the issuer matches the job %q", token.Subject)
	}
	return &Workload{Account: account, Rule: rules[i], Subject: token.Subject, JTI: jti, Expiry: token.Expiry}, nil
}

// IssueWorkloadSession ends an exchange. The row also spends the job token, a second exchange of it hits the unique
// index. It lasts an hour at most and never past the job token.
func (s *Service) IssueWorkloadSession(
	ctx context.Context,
	job *Workload,
	binding string,
) (*db.AccessToken, string, error) {
	tok, secret, err := s.IssueToken(ctx, TokenParams{
		SubjectID:   job.Account.ID,
		Kind:        actor.KindServiceAccount,
		Method:      MethodFederation,
		Binding:     binding,
		Label:       truncate(cmp.Or(job.Subject, "CI job"), 100),
		TTL:         workloadSessionTTL,
		NotAfter:    job.Expiry,
		WorkloadJTI: job.Rule.Issuer + " " + job.JTI,
	})
	if db.IsUniqueViolation(err) {
		return nil, "", &WorkloadRefusedError{
			Account: job.Account,
			Reason:  "this job token was used before",
			Signed:  true,
		}
	}
	return tok, secret, err
}

// ruleMatches takes every claim of the rule, as strings. An empty rule can't be stored and matches nothing.
func ruleMatches(want map[string]string, got map[string]any) bool {
	for name, value := range want {
		if s, ok := got[name].(string); !ok || s != value {
			return false
		}
	}
	return len(want) > 0
}

// unverifiedIssuer reads iss without checking anything, go-oidc does that with the issuer of the rule it picks.
func unverifiedIssuer(raw string) (string, error) {
	_, rest, ok := strings.Cut(raw, ".")
	if !ok {
		return "", errors.New("not a JWT")
	}
	payload, _, ok := strings.Cut(rest, ".")
	if !ok {
		return "", errors.New("not a JWT")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", err
	}
	if claims.Issuer == "" {
		return "", errors.New("no issuer")
	}
	return claims.Issuer, nil
}
