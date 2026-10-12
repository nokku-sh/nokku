package db

import "github.com/nokku-sh/nokku/core/internal/actor"

// SubjectKind values must match the grants CHECK constraint.
const (
	SubjectKindUser           = string(actor.KindUser)
	SubjectKindTeam           = "team"
	SubjectKindServiceAccount = string(actor.KindServiceAccount)
)
