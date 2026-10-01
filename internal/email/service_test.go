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
				IPAddress:  "203.0.113.7",
			},
			contains: []string{
				"New sign-in recorded.",
				"https://app.nokku.sh/profile/security",
				"Web browser",
				"203.0.113.7",
			},
		},
		{
			name: "email-change",
			data: ChangeNoticeTemplateData{
				NewEmail:   "j***@example.com",
				CancelURL:  "https://app.nokku.sh/email-change/cancel?token=t",
				Expiration: "7 days",
			},
			contains: []string{
				"Your email address is being changed.",
				"j***@example.com",
				"https://app.nokku.sh/email-change/cancel?token=t",
				"7 days",
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

func TestRenderOperatorFooter(t *testing.T) {
	t.Parallel()

	t.Run("self-hosted without operator", func(t *testing.T) {
		t.Parallel()
		body, err := render(
			"verification",
			VerificationTemplateData{VerificationURL: "https://x", Expiration: "15 minutes"},
		)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		for _, want := range []string{"this Nokku server", "tell your administrator"} {
			if !strings.Contains(body, want) {
				t.Errorf("footer does not contain %q", want)
			}
		}
		for _, unwanted := range []string{"Imprint", "Privacy", "mailto:", "©"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("footer without operator contains %q", unwanted)
			}
		}
	})

	t.Run("operator set", func(t *testing.T) {
		t.Parallel()
		op := Operator{
			Name:         "Acme GmbH",
			Address:      "Street 1, Vienna",
			SupportEmail: "help@acme.test",
			ImprintURL:   "https://acme.test/imprint",
		}
		body, err := render("verification", VerificationTemplateData{Operator: op, VerificationURL: "https://x"})
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		for _, want := range []string{"Acme GmbH", "Street 1, Vienna", "mailto:help@acme.test", "https://acme.test/imprint"} {
			if !strings.Contains(body, want) {
				t.Errorf("footer does not contain %q", want)
			}
		}
		if strings.Contains(body, ">Terms<") {
			t.Error("footer shows a Terms link without a terms URL")
		}
	})
}
