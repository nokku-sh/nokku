package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/namegen"
	"github.com/nokku-sh/nokku/internal/ssh"
)

var (
	firstNames = []string{
		"Mia", "Noah", "Lena", "Jonas", "Sofia", "Emil", "Nora", "Felix", "Hanna", "Lukas",
		"Clara", "Paul", "Elif", "Mateo", "Yuki", "Arjun", "Zoe", "Omar", "Ines", "Kai",
	}
	lastNames = []string{
		"Berger", "Novak", "Fischer", "Lindqvist", "Moreau", "Rossi", "Tanaka", "Okafor", "Silva", "Kowalski",
		"Haas", "Jansen", "Demir", "Nguyen", "Keller", "Marin", "Schmid", "Dubois", "Sato", "Costa",
	}
	teamNames = []string{
		"Platform", "Backend", "Frontend", "Data", "Security", "SRE", "Support", "QA", "Mobile", "Infrastructure",
	}
	robots    = []string{"ansible", "terraform", "github-actions", "backup", "monitoring", "deploy"}
	tags      = []string{"prod", "staging", "dev", "web", "api", "db", "cache", "eu", "us", "k8s"}
	usernames = []string{"root", "ubuntu", "deploy", "admin", "ec2-user", "ansible"}
	// Mostly members, like a real workspace. The owner is the one from boot.
	roles = []nokkuv1.WorkspaceRole{
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_VIEWER,
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR,
		nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
	}
)

type counts struct {
	users, teams, serviceAccounts, cas, targets, daemons int
}

// subjects is who can be granted an account on a server, by id.
type subjects struct {
	users, teams, serviceAccounts []string
}

func seed(ctx context.Context, q *db.Queries, ws *db.Workspace, n counts) error {
	// Unique within the run. A name another run took fails the insert.
	taken := map[string]bool{}
	fresh := func() string {
		for {
			if name := namegen.Generate(); !taken[name] {
				taken[name] = true
				return name
			}
		}
	}

	var who subjects
	for range n.users {
		first, last := pick(firstNames), pick(lastNames)
		u, err := q.CreateUser(ctx, &db.CreateUserParams{
			// .test never resolves, so no mail to these can reach anyone.
			Email: fmt.Sprintf("%s.%s%02d@nokku.test", strings.ToLower(first), strings.ToLower(last), roll(100)),
			Name:  first + " " + last,
			Role:  pick(roles),
		})
		if err != nil {
			return fmt.Errorf("user: %w", err)
		}
		who.users = append(who.users, u.ID)
	}

	for i := range n.teams {
		t, err := q.CreateTeam(ctx, &db.CreateTeamParams{
			Name: teamNames[i%len(teamNames)] + " " + fresh(),
			Tags: sample(tags, roll(3)),
		})
		if err != nil {
			return fmt.Errorf("team: %w", err)
		}
		who.teams = append(who.teams, t.ID)
		for _, u := range sample(who.users, 2+roll(4)) {
			if err := q.AddTeamMember(ctx, &db.AddTeamMemberParams{UserID: u, TeamID: t.ID}); err != nil {
				return fmt.Errorf("team member: %w", err)
			}
		}
	}

	for i := range n.serviceAccounts {
		id, err := q.CreateServiceAccount(ctx, &db.CreateServiceAccountParams{
			Name: pick(robots) + "-" + fresh(),
			Role: nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER,
			Tags: sample(tags, roll(3)),
		})
		if err != nil {
			return fmt.Errorf("service account: %w", err)
		}
		// The key is thrown away, nobody signs in as these.
		_, hash := crypto.NewKey(crypto.KeyPrefixServiceAccount)
		tok := &db.CreateAccessTokenParams{
			TokenHash: hash,
			Kind:      string(actor.KindServiceAccount),
			SubjectID: &id,
			Method:    string(iam.MethodToken),
			Label:     "seed",
		}
		if i%3 == 0 {
			tok.ExpiresAt = new(time.Now().AddDate(0, 1+roll(6), 0))
		}
		if _, err := q.CreateAccessToken(ctx, tok); err != nil {
			return fmt.Errorf("service account token: %w", err)
		}
		who.serviceAccounts = append(who.serviceAccounts, id)
	}

	// No CA on a server means the default one of the workspace.
	cas := []*string{nil}
	for range n.cas {
		ca, err := ssh.NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, 0)
		if err != nil {
			return err
		}
		row, err := q.CreateCA(ctx, &db.CreateCAParams{
			Name:       fresh() + " CA",
			PrivateKey: ca.PrivateKey,
			PublicKey:  ca.PublicKey,
			NotBefore:  ca.NotBefore,
			NotAfter:   ca.NotAfter,
			KeyType:    ca.KeyType,
			KeyBits:    ca.KeyBits,
		})
		if err != nil {
			return fmt.Errorf("certificate authority: %w", err)
		}
		cas = append(cas, &row.ID)
	}

	for range n.targets {
		t, err := q.CreateTarget(ctx, &db.CreateTargetParams{
			CaID: pick(cas),
			Name: fresh(),
			// TEST-NET-3, an address nothing answers on.
			Endpoints: []string{fmt.Sprintf("203.0.113.%d:22", 1+roll(254))},
			Tags:      sample(tags, 1+roll(2)),
		})
		if err != nil {
			return fmt.Errorf("server: %w", err)
		}
		if err := grant(ctx, q, t.ID, who); err != nil {
			return err
		}
	}

	config := db.ResolveDaemonConfig(ws.Settings.GetDefaultDaemonConfig())
	for i := range n.daemons {
		status := nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
		if i%4 == 3 {
			status = nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
		}
		// The daemon brings its server along. A taken name returns no row.
		d, err := q.CreateDaemon(ctx, &db.CreateDaemonParams{
			Name:          fresh(),
			Status:        status,
			Config:        config,
			Metadata:      []byte(`{"user-agent": "nokkud/seed (linux/amd64)"}`),
			KeyThumbprint: new(crypto.RandomString(43)),
		})
		if err != nil {
			return fmt.Errorf("daemon: %w", err)
		}
		if err := grant(ctx, q, d.TargetID, who); err != nil {
			return err
		}
	}
	return nil
}

// grant gives a server a few accounts, each with some subjects that may sign in as it.
func grant(ctx context.Context, q *db.Queries, targetID string, who subjects) error {
	for _, username := range sample(usernames, 1+roll(3)) {
		p, err := q.CreateTargetAccount(ctx, &db.CreateTargetAccountParams{TargetID: targetID, Username: username})
		if err != nil {
			return fmt.Errorf("account: %w", err)
		}
		for kind, ids := range map[string][]string{
			db.SubjectKindUser:           sample(who.users, roll(4)),
			db.SubjectKindTeam:           sample(who.teams, roll(3)),
			db.SubjectKindServiceAccount: sample(who.serviceAccounts, roll(2)),
		} {
			for _, id := range ids {
				if err := q.AddGrant(ctx, &db.AddGrantParams{
					AccountID: p.ID, SubjectKind: kind, SubjectID: id,
				}); err != nil {
					return fmt.Errorf("grant: %w", err)
				}
			}
		}
	}
	return nil
}

func roll(n int) int {
	return rand.IntN(n) //nolint:gosec // fake data, nothing here is a secret
}

func pick[T any](s []T) T {
	return s[roll(len(s))]
}

//nolint:gosec // fake data, nothing here is a secret
func sample[T any](s []T, n int) []T {
	out := slices.Clone(s)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:min(n, len(out))]
}
