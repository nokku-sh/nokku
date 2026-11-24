package audit

import (
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

const actorKindPrefix = "ACTOR_KIND_"

// ActorKindName is the kind as the log stores it.
func ActorKindName(k nokkuv1.ActorKind) string {
	return strings.ToLower(strings.TrimPrefix(k.String(), actorKindPrefix))
}

func (e *Event) ToProto() *nokkuv1.AuditEvent {
	details, err := structpb.NewStruct(e.Details)
	if err != nil {
		details = &structpb.Struct{}
	}
	return &nokkuv1.AuditEvent{
		Id:        &e.ID,
		ActorId:   &e.ActorID,
		ActorKind: nokkuv1.ActorKind(nokkuv1.ActorKind_value[actorKindPrefix+strings.ToUpper(e.ActorKind)]).Enum(),
		ActorName: &e.ActorName,
		Action:    &e.Action,
		Target:    &e.Target,
		Ok:        &e.OK,
		Ip:        &e.IP,
		UserAgent: &e.UserAgent,
		Details:   details,
		Timestamp: timestamppb.New(e.Timestamp),
	}
}
