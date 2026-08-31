package api

// Member listing joins the identity display fields onto the membership rows
// in SQL (docs/adr/0001); these helpers shape the joined rows for the API
// surface.

import (
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// workspaceMemberProto shapes a ListWorkspaceMembers row.
func workspaceMemberProto(row *db.ListWorkspaceMembersRow) *nokkuv1.WorkspaceMember {
	picture := derefStr(row.Picture)
	return &nokkuv1.WorkspaceMember{
		Id:            &row.UserID,
		WorkspaceId:   &row.WorkspaceID,
		Name:          &row.Name,
		Email:         &row.Email,
		EmailVerified: &row.EmailVerified,
		Picture:       &picture,
		RoleName:      &row.RoleName,
		CreatedAt:     db.SafeTimestamp(&row.CreatedAt),
		UpdatedAt:     db.SafeTimestamp(&row.UpdatedAt),
	}
}

// teamMemberProto shapes a ListTeamMembers row.
func teamMemberProto(row *db.ListTeamMembersRow) *nokkuv1.WorkspaceMember {
	picture := derefStr(row.Picture)
	return &nokkuv1.WorkspaceMember{
		Id:            &row.UserID,
		WorkspaceId:   &row.WorkspaceID,
		Name:          &row.Name,
		Email:         &row.Email,
		EmailVerified: &row.EmailVerified,
		Picture:       &picture,
		CreatedAt:     db.SafeTimestamp(&row.CreatedAt),
	}
}
