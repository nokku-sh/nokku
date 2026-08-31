package api

import (
	"context"
	"strings"
	"time"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// Member display fields live in kagi's user directory, not in nokku's
// membership rows. These helpers stitch the two together.

// memberUsers loads the kagi users for a set of member user IDs and indexes
// them by ID. Users are global, so the tenant is the empty value.
func memberUsers(
	ctx context.Context,
	svc *kagi.Service,
	userIDs []string,
) (map[string]kagi.User, error) {
	users, err := svc.Users.ListByIDs(ctx, "", userIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]kagi.User, len(users))
	for _, u := range users {
		out[u.ID] = u
	}
	return out, nil
}

// workspaceMemberProto combines a workspace_members row with the member's
// kagi user. A missing user degrades to empty display fields.
func workspaceMemberProto(
	workspaceID, userID, roleName string,
	createdAt, updatedAt time.Time,
	u kagi.User,
) *nokkuv1.WorkspaceMember {
	return &nokkuv1.WorkspaceMember{
		Id:            &userID,
		WorkspaceId:   &workspaceID,
		Name:          &u.DisplayName,
		Email:         &u.Email,
		EmailVerified: &u.EmailVerified,
		Picture:       &u.Picture,
		RoleName:      &roleName,
		CreatedAt:     db.SafeTimestamp(&createdAt),
		UpdatedAt:     db.SafeTimestamp(&updatedAt),
	}
}

// teamMemberProto combines a team_members row with the member's kagi user.
func teamMemberProto(
	workspaceID, userID string,
	createdAt time.Time,
	u kagi.User,
) *nokkuv1.WorkspaceMember {
	return &nokkuv1.WorkspaceMember{
		Id:            &userID,
		WorkspaceId:   &workspaceID,
		Name:          &u.DisplayName,
		Email:         &u.Email,
		EmailVerified: &u.EmailVerified,
		Picture:       &u.Picture,
		CreatedAt:     db.SafeTimestamp(&createdAt),
	}
}

// matchesMemberQuery reports whether the member's display fields contain the
// case-insensitive search query, replacing the ILIKE filter the member
// queries used to run against kagi.users.
func matchesMemberQuery(u kagi.User, query string) bool {
	if query == "" {
		return true
	}
	q := strings.ToLower(query)
	return strings.Contains(strings.ToLower(u.DisplayName), q) ||
		strings.Contains(strings.ToLower(u.Email), q)
}
