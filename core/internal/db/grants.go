package db

import (
	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

// SubjectKind values must match the generated subject_kind columns.
const (
	SubjectKindUser           = string(actor.KindUser)
	SubjectKindTeam           = "team"
	SubjectKindServiceAccount = string(actor.KindServiceAccount)
)

var SubjectKinds = map[string]nokkuv1.SubjectKind{
	SubjectKindUser:           nokkuv1.SubjectKind_SUBJECT_KIND_USER,
	SubjectKindTeam:           nokkuv1.SubjectKind_SUBJECT_KIND_TEAM,
	SubjectKindServiceAccount: nokkuv1.SubjectKind_SUBJECT_KIND_SERVICE_ACCOUNT,
}
