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
			name: "magic-link",
			data: linkTemplateData{
				LinkURL:    "https://acme.nokku.sh/login/verify?token=t",
				Expiration: "15 minutes",
			},
			contains: []string{
				"Here is your sign-in link.",
				"https://acme.nokku.sh/login/verify?token=t",
				"15 minutes",
			},
		},
		{
			name: "signup-link",
			data: signupTemplateData{
				UserName:   "Ada",
				Workspace:  "Acme",
				LinkURL:    "https://acme.nokku.sh/invite/verify?token=t",
				Expiration: "15 minutes",
			},
			contains: []string{
				"Acme.",
				"Ada",
				"https://acme.nokku.sh/invite/verify?token=t",
				"15 minutes",
			},
		},

		{
			name: "new-login",
			data: newLoginTemplateData{
				ProfileURL: "https://app.nokku.sh/profile/security",
				DeviceID:   "device-id",
				DeviceName: "Web browser",
				EventTime:  "just now",
				IPAddress:  "203.0.113.7",
			},
			contains: []string{
				"New sign-in from",
				"https://app.nokku.sh/profile/security",
				"Web browser",
				"203.0.113.7",
			},
		},
		{
			name: "email-confirm",
			data: linkTemplateData{
				LinkURL:    "https://acme.nokku.sh/email-change?token=t",
				Expiration: "1 hour",
			},
			contains: []string{
				"Confirm your new email address.",
				"https://acme.nokku.sh/email-change?token=t",
				"1 hour",
			},
		},
		{
			name: "email-change",
			data: changeNoticeTemplateData{
				NewEmail:   "j***@example.com",
				CancelURL:  "https://app.nokku.sh/email-change?cancel=1&token=t",
				Expiration: "7 days",
			},
			contains: []string{
				"Your email address is being changed.",
				"j***@example.com",
				"https://app.nokku.sh/email-change?cancel=1&amp;token=t",
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
				if !strings.Contains(body.html, want) {
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
			"magic-link",
			linkTemplateData{LinkURL: "https://x", Expiration: "15 minutes"},
		)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		for _, want := range []string{"this Nokku server", "tell your administrator"} {
			if !strings.Contains(body.html, want) {
				t.Errorf("footer does not contain %q", want)
			}
		}
		for _, unwanted := range []string{"Imprint", "Privacy", "mailto:", "©"} {
			if strings.Contains(body.html, unwanted) {
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
		body, err := render("magic-link", linkTemplateData{Operator: op, LinkURL: "https://x"})
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		for _, want := range []string{"Acme GmbH", "Street 1, Vienna", "mailto:help@acme.test", "https://acme.test/imprint"} {
			if !strings.Contains(body.html, want) {
				t.Errorf("footer does not contain %q", want)
			}
		}
		if strings.Contains(body.html, ">Terms<") {
			t.Error("footer shows a Terms link without a terms URL")
		}
	})
}
