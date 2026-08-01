package email

import (
	"context"
	"testing"
)

func TestAddress_String(t *testing.T) {
	tests := []struct {
		name string
		in   Address
		want string
	}{
		{"with name", Address{Name: "Nokku", Email: "no@x.sh"}, "Nokku <no@x.sh>"},
		{"without name", Address{Email: "no@x.sh"}, "no@x.sh"},
		{"empty", Address{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("Address.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMessage_RecipientEmails(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want []string
	}{
		{
			"single recipient",
			Message{To: []Address{{Email: "a@b.io"}}},
			[]string{"a@b.io"},
		},
		{
			"multiple recipients",
			Message{To: []Address{{Email: "a@b.io"}, {Email: "c@d.io"}}},
			[]string{"a@b.io", "c@d.io"},
		},
		{
			"empty addresses skipped",
			Message{To: []Address{{Email: "  "}, {Email: "a@b.io"}, {}}},
			[]string{"a@b.io"},
		},
		{
			"no recipients returns nil",
			Message{},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.RecipientEmails()
			if len(got) != len(tt.want) {
				t.Fatalf("RecipientEmails() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("RecipientEmails()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSenderFunc(t *testing.T) {
	called := false
	sender := SenderFunc(func(_ context.Context, msg Message) error {
		called = true
		if msg.Subject != "test" {
			t.Errorf("Subject = %q, want test", msg.Subject)
		}
		return nil
	})

	if err := sender.Send(context.Background(), Message{Subject: "test"}); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	if !called {
		t.Error("SenderFunc.Send() did not invoke the underlying function")
	}
}
