package audit

import (
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

func (e *Event) ToProto() *nokkuv1.EventLog {
	if e == nil {
		return nil
	}

	details, err := structpb.NewStruct(e.Details)
	if err != nil {
		details = &structpb.Struct{}
	}
	return &nokkuv1.EventLog{
		Id:          &e.ID,
		WorkspaceId: &e.WorkspaceID,
		ActorId:     &e.ActorID,
		ActorType:   &e.ActorType,
		ActorEmail:  &e.ActorEmail,
		Action:      &e.Action,
		IpAddress:   &e.IPAddress,
		UserAgent:   &e.UserAgent,
		StatusCode:  &e.StatusCode,
		Details:     details,
		Timestamp:   timestamppb.New(e.Timestamp),
	}
}

func EventsToProto(events []*Event) []*nokkuv1.EventLog {
	var protoEvents []*nokkuv1.EventLog
	for _, event := range events {
		protoEvents = append(protoEvents, event.ToProto())
	}
	return protoEvents
}
