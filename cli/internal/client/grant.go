package client

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"uuid"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

// lookupLimit is the most the backend lists at once. The query narrows a
// lookup to the entries that contain the name, so this is plenty.
const lookupLimit = 100

// Grant is who may log in as one account of a new manual target.
type Grant struct {
	Account string
	// Subjects are the subjects as the operator typed them, the rest is their ids.
	Subjects        []string
	Users           []string
	Teams           []string
	ServiceAccounts []string
}

// ResolveGrants reads every --grant of nk sync, written as
// account=subject,subject, and looks the subjects up. A subject is me, an
// email, team:<name>, or sa:<name>. An id in place of an email or a name is
// taken as it is, which also tells teams of one name apart.
func (c *Client) ResolveGrants(ctx context.Context, specs []string) ([]Grant, error) {
	seed, err := parseGrants(specs)
	if err != nil {
		return nil, err
	}
	grants := make([]Grant, 0, len(seed))
	for _, account := range slices.Sorted(maps.Keys(seed)) {
		var g Grant
		if g, err = c.resolveGrant(ctx, account, seed[account]); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// parseGrants gives an account that is named twice the subjects of both.
func parseGrants(specs []string) (map[string][]string, error) {
	seed := map[string][]string{}
	for _, spec := range specs {
		account, list, _ := strings.Cut(spec, "=")
		account = strings.TrimSpace(account)
		var subjects []string
		for subject := range strings.SplitSeq(list, ",") {
			if subject = strings.TrimSpace(subject); subject != "" {
				subjects = append(subjects, subject)
			}
		}
		if account == "" || len(subjects) == 0 {
			return nil, fmt.Errorf("--grant %q is not account=subject, for example --grant root=me", spec)
		}
		seed[account] = append(seed[account], subjects...)
	}
	return seed, nil
}

func (c *Client) resolveGrant(ctx context.Context, account string, subjects []string) (Grant, error) {
	g := Grant{Account: account, Subjects: subjects}
	for _, ref := range subjects {
		kind, name, prefixed := strings.Cut(ref, ":")
		var err error
		var id string
		switch {
		case ref == "me" && c.State.ServiceAccount != nil:
			g.ServiceAccounts = append(g.ServiceAccounts, c.State.ServiceAccount.ID)
		case ref == "me" && c.State.User != nil:
			g.Users = append(g.Users, c.State.User.ID)
		case ref == "me":
			err = errors.New("who is me? Run nk login first")
		case !prefixed:
			id, err = c.userID(ctx, ref)
			g.Users = append(g.Users, id)
		case kind == "team":
			id, err = c.teamID(ctx, name)
			g.Teams = append(g.Teams, id)
		case kind == "sa":
			id, err = c.serviceAccountID(ctx, name)
			g.ServiceAccounts = append(g.ServiceAccounts, id)
		default:
			err = fmt.Errorf("%q is not me, an email, team:<name>, or sa:<name>", ref)
		}
		if err != nil {
			return Grant{}, err
		}
	}
	return g, nil
}

func (c *Client) userID(ctx context.Context, email string) (string, error) {
	if isID(email) {
		return email, nil
	}
	res, err := c.users.ListUsers(ctx, &nokkuv1.ListUsersRequest{
		Query: new(email),
		Limit: new(int32(lookupLimit)),
	})
	if err != nil {
		return "", fmt.Errorf("looking up %s: %w", email, err)
	}
	var ids []string
	for _, u := range res.GetUsers() {
		if strings.EqualFold(u.GetEmail(), email) {
			ids = append(ids, u.GetId())
		}
	}
	return oneID(ids, "user", email)
}

func (c *Client) teamID(ctx context.Context, name string) (string, error) {
	if isID(name) {
		return name, nil
	}
	res, err := c.teams.ListTeams(ctx, &nokkuv1.ListTeamsRequest{
		Query: new(name),
		Limit: new(int32(lookupLimit)),
	})
	if err != nil {
		return "", fmt.Errorf("looking up team %s: %w", name, err)
	}
	var ids []string
	for _, t := range res.GetTeams() {
		if t.GetName() == name {
			ids = append(ids, t.GetId())
		}
	}
	return oneID(ids, "team", name)
}

func (c *Client) serviceAccountID(ctx context.Context, name string) (string, error) {
	if isID(name) {
		return name, nil
	}
	res, err := c.serviceAccounts.ListServiceAccounts(ctx, &nokkuv1.ListServiceAccountsRequest{
		Query: new(name),
		Limit: new(int32(lookupLimit)),
	})
	if err != nil {
		return "", fmt.Errorf("looking up service account %s: %w", name, err)
	}
	var ids []string
	for _, sa := range res.GetServiceAccounts() {
		if sa.GetName() == name {
			ids = append(ids, sa.GetId())
		}
	}
	return oneID(ids, "service account", name)
}

// oneID refuses a name that fits nothing or several. Team names are not
// unique on the backend.
func oneID(ids []string, kind, name string) (string, error) {
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("there is no %s %q in this workspace", kind, name)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("several %ss are named %q, pass the id", kind, name)
}

func isID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}
