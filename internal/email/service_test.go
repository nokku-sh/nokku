package email

import (
	"strings"
	"testing"
)

func TestRenderTemplates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     any
		contains []string
	}{
		{
			name: "welcome",
			data: WelcomeTemplateData{
				UserName:        "Ada",
				VerificationURL: "https://app.nokku.sh/verify/token",
				Expiration:      "15 minutes",
			},
			contains: []string{
				"Welcome aboard,",
				"Ada",
				"https://app.nokku.sh/verify/token",
				"15 minutes",
			},
		},
		{
			name: "verification",
			data: VerificationTemplateData{
				VerificationURL: "https://app.nokku.sh/verify/token",
				Expiration:      "15 minutes",
			},
			contains: []string{
				"Verify your email address.",
				"https://app.nokku.sh/verify/token",
				"15 minutes",
			},
		},
		{
			name: "recovery",
			data: RecoveryTemplateData{
				RecoveryURL: "https://app.nokku.sh/reset/token",
				Expiration:  "15 minutes",
			},
			contains: []string{
				"Reset your password.",
				"https://app.nokku.sh/reset/token",
				"15 minutes",
			},
		},

		{
			name: "new-login",
			data: NewLoginTemplateData{
				ProfileURL: "https://app.nokku.sh/profile/security",
				DeviceID:   "device-id",
				DeviceName: "Web browser",
				EventTime:  "just now",
				Location:   "Innsbruck, Austria",
			},
			contains: []string{
				"New sign-in recorded.",
				"https://app.nokku.sh/profile/security",
				"Password",
				"Web browser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, err := render(tt.name, tt.data)
			if err != nil {
				t.Fatalf("render(%q): %v", tt.name, err)
			}

			for _, want := range tt.contains {
				if !strings.Contains(body, want) {
					t.Errorf("render(%q) does not contain %q", tt.name, want)
				}
			}
		})
	}
}
