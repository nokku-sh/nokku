package db

import "github.com/nokku-sh/nokku/internal/actor"

// SubjectKind values stored in principal_grants.subject_kind. The CHECK
// constraint in 001_base.sql is the authority: a grant subject is a user, a
// team, or a service account. Users and service accounts share the actor
// vocabulary, teams exist only as grant subjects and never authenticate.
const (
	SubjectKindUser           = string(actor.KindUser)
	SubjectKindTeam           = "team"
	SubjectKindServiceAccount = string(actor.KindServiceAccount)
)
