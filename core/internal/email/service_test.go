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
			name: "access-request",
			data: accessRequestTemplateData{
				Requester:  "Ada",
				Target:     "web-1",
				Account:    "deploy",
				Duration:   "2 hours",
				Reason:     "fix <the> deploy",
				RequestURL: "https://acme.nokku.sh/access/requests?id=r1",
				RequestID:  "r1",
			},
			contains: []string{
				"Ada asks for access.",
				"deploy on web-1 for 2 hours",
				"https://acme.nokku.sh/access/requests?id=r1",
			},
		},
		{
			name: "access-request-decided",
			data: accessDecisionTemplateData{
				Decision:   "approved",
				Decider:    "Grace",
				Target:     "web-1",
				Account:    "deploy",
				Until:      "18 Oct 2026, 20:00 UTC",
				RequestURL: "https://acme.nokku.sh/access/requests?id=r1",
				RequestID:  "r1",
			},
			contains: []string{
				"Your request was approved.",
				"You can log in until 18 Oct 2026, 20:00 UTC.",
				"Connect with ssh as usual.",
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
		{
			name: "trial-ending",
			data: trialTemplateData{
				Operator:   Operator{SupportEmail: "help@nokku.sh"},
				Workspace:  "Acme",
				Left:       "7 days",
				EndDate:    "23 Oct 2026",
				DeleteDate: "22 Nov 2026",
				BillingURL: "https://acme.nokku.sh/settings/billing",
				Next:       "3 days",
			},
			contains: []string{
				"Your trial ends in",
				"The Pro trial of Acme ends in 7 days.",
				"23 Oct 2026",
				"22 Nov 2026",
				"https://acme.nokku.sh/settings/billing",
				"One more reminder comes 3 days",
				"help@nokku.sh",
			},
		},
		{
			name: "workspace-deletion",
			data: deletionTemplateData{
				Workspace:  "Acme",
				Slug:       "acme",
				EndDate:    "16 Apr 2026",
				DeleteDate: "13 Oct 2026",
				BillingURL: "https://acme.nokku.sh/settings/billing",
				Next:       "7 days",
			},
			contains: []string{
				"Acme is deleted on 13 Oct 2026.",
				"plan",
				"16 Apr 2026",
				"acme",
				"https://acme.nokku.sh/settings/billing",
				"One more warning comes 7 days before",
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

func TestRenderTrialEnding_LastReminderPromisesNoOther(t *testing.T) {
	t.Parallel()
	body, err := render("trial-ending", trialTemplateData{Workspace: "Acme", Left: inDays(1)})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{body.html, body.text} {
		if strings.Contains(part, "One more reminder") {
			t.Error("the 3 day reminder is the last one")
		}
		if !strings.Contains(part, "ends in 1 day.") {
			t.Error("one day is singular")
		}
	}
}
