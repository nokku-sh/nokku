package db

import "github.com/nokku-sh/nokku/internal/actor"

// SubjectKind values must match the principal_grants CHECK constraint.
const (
	SubjectKindUser           = string(actor.KindUser)
	SubjectKindTeam           = "team"
	SubjectKindServiceAccount = string(actor.KindServiceAccount)
)
