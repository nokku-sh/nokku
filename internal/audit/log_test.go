package audit

import "testing"

func TestShouldAuditHTTPProcedures(t *testing.T) {
	tests := []struct {
		name      string
		procedure string
		want      bool
	}{
		{name: "oauth login", procedure: "GET /oauth/login", want: true},
		{name: "oauth callback", procedure: "GET /oauth/callback", want: true},
		{name: "saml login", procedure: "GET /saml/login", want: true},
		{name: "passkey login", procedure: "POST /passkey/login/begin", want: true},
		{name: "stripe webhook", procedure: "POST /webhooks/stripe", want: true},
		{name: "avatar upload", procedure: "POST /upload/avatar", want: true},
		{name: "public asset", procedure: "GET /avatars/id", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAudit(tt.procedure); got != tt.want {
				t.Fatalf("shouldAudit(%q) = %v, want %v", tt.procedure, got, tt.want)
			}
		})
	}
}
