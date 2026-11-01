package db

import "github.com/nokku-sh/nokku/core/internal/actor"

// SubjectKind values must match the generated subject_kind columns.
const (
	SubjectKindUser           = string(actor.KindUser)
	SubjectKindTeam           = "team"
	SubjectKindServiceAccount = string(actor.KindServiceAccount)
)
