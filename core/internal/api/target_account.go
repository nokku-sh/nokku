package api

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// A plan names this many servers, the counts say how many there are.
const grantNamesShown = 5

type targetAccountService struct {
	cfg *app.Config
}

func (s *targetAccountService) ListTargetAccounts(
	ctx context.Context,
	req *nokkuv1.ListTargetAccountsRequest,
) (*nokkuv1.ListTargetAccountsResponse, error) {
	q := s.cfg.Conn.Tenant()
	params := &db.ListTargetAccountsParams{
		TargetID: req.GetTargetId(),
		Query:    req.Query,
		Limit:    req.Limit,
		Offset:   req.Offset,
	}
	accounts, err := q.ListTargetAccounts(ctx, params)
	if err != nil {
		return nil, err
	}
	counted := accounts
	if len(accounts) == 0 && req.GetOffset() > 0 {
		// A page past the end has no row to carry the total, the first row does.
		params.Limit, params.Offset = new(int32(1)), nil
		if counted, err = q.ListTargetAccounts(ctx, params); err != nil {
			return nil, err
		}
	}
	var count int32
	if len(counted) > 0 {
		count = counted[0].TotalCount
	}

	return &nokkuv1.ListTargetAccountsResponse{
		Accounts: db.TargetAccountsToProto(accounts),
		Total:    &count,
	}, nil
}

func (s *targetAccountService) GetGrantScope(
	ctx context.Context,
	req *nokkuv1.GetGrantScopeRequest,
) (*nokkuv1.GetGrantScopeResponse, error) {
	res := &nokkuv1.GetGrantScopeResponse{}
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		targets, err := q.GrantWhere(ctx, &db.GrantWhereParams{TargetIds: req.GetTargetIds(), Tags: req.GetTags()})
		if err != nil {
			return err
		}
		res.TargetCount = new(int32(len(targets))) //nolint:gosec // rows of one workspace
		for _, t := range targets[:min(len(targets), grantNamesShown)] {
			res.TargetNames = append(res.TargetNames, t.Name)
		}
		accounts, err := q.GrantWhereAccounts(ctx, &db.GrantWhereAccountsParams{
			TargetIds: req.GetTargetIds(), Tags: req.GetTags(),
		})
		if err != nil {
			return err
		}
		for _, a := range accounts {
			res.Accounts = append(res.Accounts, &nokkuv1.GrantAccount{Username: &a.Username, TargetCount: &a.Servers})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *targetAccountService) Grant(
	ctx context.Context,
	req *nokkuv1.GrantRequest,
) (*nokkuv1.GrantResponse, error) {
	spec, write := req.GetGrant(), !req.GetDryRun()
	if subjects := spec.GetSubjects(); write && len(subjects) == 1 {
		// An event is about one thing. A grant to several subjects names them in its details only.
		audit.SetTarget(ctx, subjects[0].GetId())
	}
	plan := &nokkuv1.GrantPlan{}
	var expiresAt *time.Time
	if spec.GetExpiresAt() != nil {
		expiresAt = new(spec.GetExpiresAt().AsTime())
	}
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		servers, err := q.GrantWhere(ctx, &db.GrantWhereParams{
			Username: spec.GetUsername(), TargetIds: spec.GetTargetIds(), Tags: spec.GetTags(),
		})
		if err != nil {
			return err
		}
		var accountIDs, named []string
		for _, server := range servers {
			switch {
			case server.AccountID != nil:
				accountIDs = append(accountIDs, *server.AccountID)
				if slices.Contains(spec.GetTargetIds(), server.ID) {
					named = append(named, server.Name)
				}
			case len(plan.GetSkippedTargetNames()) < grantNamesShown:
				plan.SkippedTargetNames = append(plan.SkippedTargetNames, server.Name)
			}
		}
		plan.TargetCount = new(int32(len(servers)))           //nolint:gosec // rows of one workspace
		plan.MatchedTargetCount = new(int32(len(accountIDs))) //nolint:gosec // rows of one workspace

		var subjects []string
		var added, changed int32
		for _, subject := range spec.GetSubjects() {
			standing, err := q.ListGrantEnds(ctx, &db.ListGrantEndsParams{
				AccountIds: accountIDs, SubjectID: subject.GetId(),
			})
			if err != nil {
				return err
			}
			ends := make(map[string]*time.Time, len(standing))
			for _, g := range standing {
				ends[g.AccountID] = g.ExpiresAt
			}
			var fresh, same, otherEnd int32
			var put []string
			for _, accountID := range accountIDs {
				end, held := ends[accountID]
				switch {
				case !held:
					fresh++
				case sameEnd(end, expiresAt):
					same++
					continue
				default:
					otherEnd++
					if !spec.GetOverwriteExpiry() {
						continue
					}
				}
				put = append(put, accountID)
			}
			plan.Outcomes = append(plan.Outcomes, &nokkuv1.GrantOutcome{
				SubjectId: subject.Id, AddedCount: &fresh, UnchangedCount: &same, OtherExpiryCount: &otherEnd,
			})
			subjects = append(subjects, subject.GetId())
			added += fresh
			if spec.GetOverwriteExpiry() {
				changed += otherEnd
			}
			if !write || len(put) == 0 {
				continue
			}
			if err := q.PutGrants(ctx, &db.PutGrantsParams{
				AccountIds: put, SubjectKind: subjectKind(subject.GetKind()), SubjectID: subject.GetId(),
				ExpiresAt: expiresAt,
				GrantedBy: callerID(ctx),
			}); err != nil {
				return err
			}
		}
		if !write {
			return nil
		}
		names, err := q.GetNames(ctx, subjects)
		if err != nil {
			return err
		}
		audit.Set(ctx, "subjects", names)
		audit.Set(ctx, "username", spec.GetUsername())
		audit.Set(ctx, "tags", spec.GetTags())
		// A tag says which servers, the ones picked by id go by name.
		if len(named) > 0 {
			audit.Set(ctx, "targets", named)
		}
		audit.Set(ctx, "servers", plan.GetMatchedTargetCount())
		audit.Set(ctx, "added", added)
		audit.Set(ctx, "changed", changed)
		if expiresAt != nil {
			audit.Set(ctx, "expires_at", *expiresAt)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.GrantResponse{Plan: plan}, nil
}

// sameEnd compares to the second, which is what the web app sends.
func sameEnd(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Unix() == b.Unix()
}

func (s *targetAccountService) Revoke(
	ctx context.Context,
	req *nokkuv1.RevokeRequest,
) (*nokkuv1.RevokeResponse, error) {
	spec, write := req.GetRevoke(), !req.GetDryRun()
	audit.SetTarget(ctx, spec.GetSubject().GetId())
	kind := subjectKind(spec.GetSubject().GetKind())
	plan := &nokkuv1.RevokePlan{}
	err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		held, err := q.RevokeWhere(ctx, &db.RevokeWhereParams{
			SubjectKind: kind, SubjectID: spec.GetSubject().GetId(),
			Everywhere: spec.GetAllTargets(), TargetIds: spec.GetTargetIds(), Tags: spec.GetTags(),
			Username: spec.GetUsername(),
		})
		if err != nil {
			return err
		}
		type account struct {
			servers int32
			names   []string
		}
		accounts := map[string]*account{}
		servers := map[string]bool{}
		var accountIDs, named []string
		var otherTags int32
		for _, g := range held {
			accountIDs = append(accountIDs, g.AccountID)
			a := accounts[g.Username]
			if a == nil {
				a = &account{}
				accounts[g.Username] = a
			}
			a.servers++
			if len(a.names) < grantNamesShown {
				a.names = append(a.names, g.Name)
			}
			if servers[g.TargetID] {
				continue
			}
			servers[g.TargetID] = true
			if slices.Contains(spec.GetTargetIds(), g.TargetID) {
				named = append(named, g.Name)
			}
			if !g.OtherTags {
				continue
			}
			otherTags++
			if len(plan.GetMultiTagTargetNames()) < grantNamesShown {
				plan.MultiTagTargetNames = append(plan.MultiTagTargetNames, g.Name)
			}
		}
		usernames := slices.SortedFunc(maps.Keys(accounts), func(a, b string) int {
			return cmp.Or(cmp.Compare(accounts[b].servers, accounts[a].servers), cmp.Compare(a, b))
		})
		for _, username := range usernames {
			plan.Accounts = append(plan.Accounts, &nokkuv1.RevokeAccount{
				Username: &username, TargetCount: &accounts[username].servers, TargetNames: accounts[username].names,
			})
		}
		plan.GrantCount = new(int32(len(held)))     //nolint:gosec // rows of one workspace
		plan.TargetCount = new(int32(len(servers))) //nolint:gosec // rows of one workspace
		plan.MultiTagTargetCount = &otherTags
		if !write {
			return nil
		}
		if err := q.RemoveGrants(ctx, &db.RemoveGrantsParams{
			AccountIds: accountIDs, SubjectKind: kind, SubjectID: spec.GetSubject().GetId(),
		}); err != nil {
			return err
		}
		names, err := q.GetNames(ctx, []string{spec.GetSubject().GetId()})
		if err != nil {
			return err
		}
		audit.Set(ctx, "subject_kind", kind)
		audit.Set(ctx, "subjects", names)
		audit.Set(ctx, "usernames", usernames)
		audit.Set(ctx, "tags", spec.GetTags())
		if len(named) > 0 {
			audit.Set(ctx, "targets", named)
		}
		if spec.GetAllTargets() {
			audit.Set(ctx, "everywhere", true)
		}
		audit.Set(ctx, "servers", plan.GetTargetCount())
		audit.Set(ctx, "removed", plan.GetGrantCount())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.RevokeResponse{Plan: plan}, nil
}

// AddTargetAccount is for manual targets, no daemon reports their accounts.
func (s *targetAccountService) AddTargetAccount(
	ctx context.Context,
	req *nokkuv1.AddTargetAccountRequest,
) (*nokkuv1.AddTargetAccountResponse, error) {
	q := s.cfg.Conn.Tenant()
	audit.Set(ctx, "username", req.GetUsername())
	if err := auditName(ctx, q, "target", req.GetTargetId()); err != nil {
		return nil, err
	}
	account, err := q.CreateTargetAccount(ctx, &db.CreateTargetAccountParams{
		TargetID: req.GetTargetId(),
		Username: req.GetUsername(),
	})
	if err != nil {
		return nil, err
	}

	return &nokkuv1.AddTargetAccountResponse{Account: account.ToProto()}, nil
}

func (s *targetAccountService) RemoveTargetAccount(
	ctx context.Context,
	req *nokkuv1.RemoveTargetAccountRequest,
) (*nokkuv1.RemoveTargetAccountResponse, error) {
	q := s.cfg.Conn.Tenant()
	// Removing an account that is gone stays a no-op, it just has no names.
	if err := auditAccount(ctx, q, req.GetId()); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := q.DeleteTargetAccount(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return &nokkuv1.RemoveTargetAccountResponse{}, nil
}

// auditAccount names a login account by its server and username.
func auditAccount(ctx context.Context, q *db.Queries, accountID string) error {
	acc, err := q.GetTargetAccountLabel(ctx, accountID)
	if err != nil {
		return err
	}
	audit.Set(ctx, "target", acc.TargetName)
	audit.Set(ctx, "username", acc.Username)
	return nil
}

func subjectKind(k nokkuv1.SubjectKind) string {
	for name, kind := range db.SubjectKinds {
		if kind == k {
			return name
		}
	}
	return ""
}
