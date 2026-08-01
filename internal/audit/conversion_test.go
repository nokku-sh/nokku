package audit

import (
	"testing"
	"time"
)

func TestEvent_ToProto(t *testing.T) {
	ts := time.Date(2026, 8, 1, 12, 30, 45, 0, time.UTC)
	e := &Event{
		ID:          "evt-1",
		Timestamp:   ts,
		WorkspaceID: "ws-1",
		Action:      "login",
		ActorID:     "user-1",
		ActorType:   "user",
		IPAddress:   "203.0.113.1",
		UserAgent:   "curl/8.0",
		StatusCode:  "200",
	}

	proto := e.ToProto()
	if proto == nil {
		t.Fatal("ToProto() = nil")
	}

	if proto.GetId() != "evt-1" ||
		proto.GetWorkspaceId() != "ws-1" ||
		proto.GetActorId() != "user-1" ||
		proto.GetActorType() != "user" ||
		proto.GetAction() != "login" ||
		proto.GetIpAddress() != "203.0.113.1" ||
		proto.GetUserAgent() != "curl/8.0" ||
		proto.GetStatusCode() != "200" {
		t.Errorf("ToProto() = %+v, fields do not match event", proto)
	}
	if !proto.GetTimestamp().AsTime().Equal(ts) {
		t.Errorf("timestamp = %v, want %v", proto.GetTimestamp().AsTime(), ts)
	}
}

func TestEvent_ToProto_Nil(t *testing.T) {
	var e *Event
	if got := e.ToProto(); got != nil {
		t.Errorf("ToProto() on nil event = %v, want nil", got)
	}
}

func TestEventsToProto(t *testing.T) {
	ts := time.Now().Truncate(time.Millisecond)
	events := []*Event{
		{ID: "a", Timestamp: ts, Action: "login"},
		{ID: "b", Timestamp: ts, Action: "logout"},
	}

	protos := EventsToProto(events)
	if len(protos) != 2 {
		t.Fatalf("got %d events, want 2", len(protos))
	}
	if protos[0].GetId() != "a" || protos[1].GetId() != "b" {
		t.Errorf("unexpected ids: %q, %q", protos[0].GetId(), protos[1].GetId())
	}
}

func TestEventsToProto_NilElement(t *testing.T) {
	protos := EventsToProto([]*Event{nil})
	if len(protos) != 1 || protos[0] != nil {
		t.Errorf("EventsToProto([nil]) = %v, want [nil]", protos)
	}
}

func TestEventsToProto_Empty(t *testing.T) {
	if got := EventsToProto(nil); len(got) != 0 {
		t.Errorf("EventsToProto(nil) = %v, want empty", got)
	}
}
