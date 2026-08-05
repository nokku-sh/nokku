package seed

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/brianvoe/gofakeit/v7"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/ssh"
	"github.com/nokku-sh/nokku/internal/util"
)

func uniqueName(base string, i int) string {
	return fmt.Sprintf("%s-%d", base, i)
}

type Config struct {
	NumUsers           int
	NumTeams           int
	NumTargets         int
	NumDaemons         int
	NumCAs             int
	NumServiceAccounts int
}

func DefaultConfig() Config {
	return Config{
		NumUsers:           10,
		NumTeams:           5,
		NumTargets:         10,
		NumDaemons:         10,
		NumCAs:             2,
		NumServiceAccounts: 5,
	}
}

func Workspace(ctx context.Context, conn *db.Connection, cfg Config) error {
	_ = gofakeit.Seed(time.Now().UnixNano())

	// Create owner user
	email := os.Getenv("NOKKU_ADMIN_EMAIL")
	owner, err := conn.Q.GetUserByEmail(ctx, email)
	if err != nil {
		hash, err := crypto.HashPassword(os.Getenv("NOKKU_ADMIN_PASSWORD"))
		if err != nil {
			return fmt.Errorf("failed to hash admin password: %w", err)
		}

		owner, err = conn.Q.CreateUser(ctx, &db.CreateUserParams{
			Name:         "Super Admin",
			Username:     "admin",
			Email:        email,
			PasswordHash: hash,
		})
		if err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		if err := conn.Q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
			UserID: owner.ID,
			Email:  email,
		}); err != nil {
			return fmt.Errorf("failed to verify admin user email: %w", err)
		}
	}

	// Create workspace with a unique name
	workspace, err := conn.Q.CreateWorkspace(ctx, &db.CreateWorkspaceParams{
		Name:        uniqueName(gofakeit.Company(), 0),
		Description: new(gofakeit.Sentence()),
		CreatedBy:   owner.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	actor := &meta.Actor{
		ID:   owner.ID,
		Name: owner.Username,
		Type: meta.ActorTypeUser,
	}
	ctx = meta.WithActor(ctx, actor)

	err = conn.WithWorkspace(ctx, func(q *db.Queries) error {
		samlKeyPair, err := util.CreateSAMLKeyPair(workspace.ID)
		if err != nil {
			return err
		}

		if _, err = q.UpdateSAMLProvider(ctx, &db.UpdateSAMLProviderParams{
			WorkspaceID:   workspace.ID,
			SpPrivateKey:  crypto.EncryptedBytes(samlKeyPair.PrivateKey),
			SpCertificate: &samlKeyPair.Certificate,
		}); err != nil {
			slog.Debug("failed to create default SAML provider", "error", err)
			return err
		}

		// Create additional users; index-suffixed email/username avoids UNIQUE violations
		users := make([]*db.User, cfg.NumUsers-1)
		for i := range cfg.NumUsers - 1 {
			user, err := q.CreateUser(ctx, &db.CreateUserParams{
				Name:         gofakeit.Name(),
				Username:     gofakeit.Username(),
				Email:        gofakeit.Email(),
				PasswordHash: owner.PasswordHash,
			})
			if err != nil {
				return fmt.Errorf("failed to create user %d: %w", i, err)
			}
			if gofakeit.Bool() {
				if err := q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
					UserID: user.ID,
					Email:  user.Email,
				}); err != nil {
					return fmt.Errorf("failed to verify user email: %w", err)
				}
			}

			users[i] = user
			if err := q.AddWorkspaceMember(ctx, &db.AddWorkspaceMemberParams{
				WorkspaceID: workspace.ID,
				UserID:      user.ID,
			}); err != nil {
				return fmt.Errorf("failed to add workspace member: %w", err)
			}
		}

		// Create teams; index-suffixed names avoid UNIQUE (workspace_id, name) violations
		teams := make([]*db.Team, cfg.NumTeams)
		for i := range cfg.NumTeams {
			team, err := q.CreateTeam(ctx, &db.CreateTeamParams{
				WorkspaceID: workspace.ID,
				Name:        uniqueName(gofakeit.JobTitle(), i),
				Description: new(gofakeit.Sentence()),
			})
			if err != nil {
				return fmt.Errorf("failed to create team %d: %w", i, err)
			}
			teams[i] = team

			numberOfMembers := min(gofakeit.IntRange(2, 5), len(users))
			shuffledUsers := make([]*db.User, len(users))
			copy(shuffledUsers, users)
			gofakeit.ShuffleAnySlice(shuffledUsers)

			for j := range numberOfMembers {
				if err := q.AddTeamMember(ctx, &db.AddTeamMemberParams{
					TeamID: team.ID,
					UserID: shuffledUsers[j].ID,
				}); err != nil {
					slog.Error("failed to add team member", "error", err)
				}
			}
		}

		// Create service accounts; index-suffixed names avoid UNIQUE (workspace_id, name) violations
		sa := make([]*db.ServiceAccount, cfg.NumServiceAccounts)
		for i := range cfg.NumServiceAccounts {
			token, err := crypto.NewServiceAccountToken()
			if err != nil {
				return fmt.Errorf("failed to generate service account token: %w", err)
			}
			s, err := q.CreateServiceAccount(ctx, &db.CreateServiceAccountParams{
				ID:          token.ID,
				WorkspaceID: workspace.ID,
				TokenHash:   token.Hash,
				Name:        uniqueName(gofakeit.AppName(), i),
				Description: new(gofakeit.Sentence()),
				ExpiresAt:   new(gofakeit.FutureDate()),
			})
			if err != nil {
				return fmt.Errorf("failed to create service account %d: %w", i, err)
			}
			sa[i] = s
		}

		// Create CAs; the first one is the workspace default
		cas := make([]*db.CertificateAuthority, cfg.NumCAs)
		for i := range cfg.NumCAs {
			ca, err := ssh.NewCA(nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519, 0, 0)
			if err != nil {
				slog.Debug("failed to create CA", "error", err)
				return err
			}
			newCA, err := q.CreateCA(ctx, &db.CreateCAParams{
				WorkspaceID:  workspace.ID,
				Name:         uniqueName("CA", i),
				Description:  new(gofakeit.Sentence()),
				Certificate:  string(ca.Certificate),
				PrivateKey:   ca.PrivateKey,
				PublicKey:    ca.PublicKey,
				SerialNumber: ca.SerialNumber,
				Subject:      ca.Subject,
				IsDefault:    i == 0,
				NotBefore:    ca.NotBefore,
				NotAfter:     ca.NotAfter,
				KeyType:      ca.KeyType,
				KeyBits:      ca.KeyBits,
			})
			if err != nil {
				return fmt.Errorf("failed to insert CA: %w", err)
			}
			cas[i] = newCA
		}

		tags := []string{
			"web", "api", "db", "app", "kubernetes", "docker", "cicd",
			"devops", "monitoring", "logging", "security", "networking",
			"storage", "backup", "loadbalancer", "dns", "certificate",
		}

		for i := range cfg.NumTargets {
			shuffledTags := make([]string, len(tags))
			copy(shuffledTags, tags)
			gofakeit.ShuffleStrings(shuffledTags)
			selectedTags := shuffledTags[:gofakeit.IntRange(1, 2)]

			var endpoints []string
			for range gofakeit.IntRange(1, 4) {
				endpoints = append(endpoints, gofakeit.IPv4Address())
			}

			desc := gofakeit.Sentence()

			// Use index-suffixed name to avoid UNIQUE (workspace_id, name) violations
			target, err := q.CreateTarget(ctx, &db.CreateTargetParams{
				WorkspaceID: workspace.ID,
				Name:        uniqueName(gofakeit.AppName(), i),
				Description: &desc,
				Endpoints:   endpoints,
				Tags:        selectedTags,
				CaID:        &cas[0].ID,
			})
			if err != nil {
				return fmt.Errorf("failed to create target %d: %w", i, err)
			}

			usernames := []string{
				"root",
				"ubuntu",
				"admin",
				"deploy",
				"ec2-user",
				"ansible",
				"cicd",
			}
			// Pick 1-3 unique principals per target
			numPrincipals := gofakeit.IntRange(1, 3)
			gofakeit.ShuffleStrings(usernames)
			selectedUsernames := usernames[:min(numPrincipals, len(usernames))]

			for _, username := range selectedUsernames {
				principal, err := q.CreatePrincipal(ctx, &db.CreatePrincipalParams{
					WorkspaceID: target.WorkspaceID,
					TargetID:    target.ID,
					Username:    username,
				})
				if err != nil {
					return fmt.Errorf("failed to create principal: %w", err)
				}

				shuffledUsers := make([]*db.User, len(users))
				copy(shuffledUsers, users)
				gofakeit.ShuffleAnySlice(shuffledUsers)

				numUsers := gofakeit.IntRange(1, min(5, len(users)))
				userIDs := make([]string, numUsers)
				for k := range userIDs {
					userIDs[k] = shuffledUsers[k].ID
				}

				for _, userID := range userIDs {
					if err := q.AddUserToPrincipal(ctx, &db.AddUserToPrincipalParams{
						WorkspaceID: principal.WorkspaceID,
						PrincipalID: principal.ID,
						UserID:      userID,
					}); err != nil {
						return fmt.Errorf("failed to assign principal users: %w", err)
					}
				}

				shuffledTeams := make([]*db.Team, len(teams))
				copy(shuffledTeams, teams)
				gofakeit.ShuffleAnySlice(shuffledTeams)

				numTeams := gofakeit.IntRange(1, min(3, len(teams)))
				teamIDs := make([]string, numTeams)
				for k := range teamIDs {
					teamIDs[k] = shuffledTeams[k].ID
				}

				for _, teamID := range teamIDs {
					if err := q.AddTeamToPrincipal(ctx, &db.AddTeamToPrincipalParams{
						WorkspaceID: principal.WorkspaceID,
						PrincipalID: principal.ID,
						TeamID:      teamID,
					}); err != nil {
						return fmt.Errorf("failed to assign principal teams: %w", err)
					}
				}

				numSA := gofakeit.IntRange(0, min(2, len(sa)))
				if numSA > 0 {
					saIDs := make([]string, numSA)
					for k := range saIDs {
						saIDs[k] = sa[k].ID
					}
					for _, saID := range saIDs {
						if err := q.AddServiceAccountToPrincipal(
							ctx,
							&db.AddServiceAccountToPrincipalParams{
								WorkspaceID:      principal.WorkspaceID,
								PrincipalID:      principal.ID,
								ServiceAccountID: saID,
							},
						); err != nil {
							return fmt.Errorf("failed to assign principal service accounts: %w", err)
						}
					}
				}
			}
		}

		for i := range cfg.NumDaemons {
			status := nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
			if gofakeit.Bool() {
				status = nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
			}

			token, err := crypto.NewDaemonToken()
			if err != nil {
				return fmt.Errorf("failed to generate daemon token: %w", err)
			}
			_, err = q.CreateDaemon(ctx, &db.CreateDaemonParams{
				ID:          token.ID,
				WorkspaceID: workspace.ID,
				Name:        uniqueName(gofakeit.AppName(), i),
				Status:      status,
				TokenHash:   token.Hash,
			})
			if err != nil {
				return fmt.Errorf("failed to create daemon %d: %w", i, err)
			}
		}

		return nil
	})

	return err
}
