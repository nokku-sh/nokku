package audit

import (
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func (e *Event) ToProto() *nokkuv1.EventLog {
	details, err := structpb.NewStruct(e.Details)
	if err != nil {
		details = &structpb.Struct{}
	}
	return &nokkuv1.EventLog{
		Id:        &e.ID,
		ActorId:   &e.ActorID,
		ActorKind: &e.ActorKind,
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
