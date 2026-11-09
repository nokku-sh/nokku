package entitlement

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/mizuchilabs/inkan/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
)

const day = 24 * time.Hour

var testSigner, testPublicKey = func() (ed25519.PrivateKey, string) {
	privB64, pubHex, err := license.GenerateKey()
	if err != nil {
		panic(err)
	}
	priv, err := license.ParsePrivateKey(privB64)
	if err != nil {
		panic(err)
	}
	return priv, pubHex
}()

var (
	selfHosted = newService(nil, testPublicKey, false)
	hosted     = newService(nil, testPublicKey, true)
)

// issue signs a key of that plan. A validFor of 0 never expires.
func issue(t *testing.T, plan string, validFor time.Duration) string {
	t.Helper()
	claims := license.Claims{Plan: plan}
	if validFor != 0 {
		claims.ExpiresAt = time.Now().Add(validFor).Unix()
	}
	key, err := license.Issue(licenseApp, claims, testSigner)
	require.NoError(t, err)
	return key
}

func issueSeats(t *testing.T, plan string, validFor time.Duration, seats string) string {
	t.Helper()
	claims := license.Claims{
		Plan:      plan,
		ExpiresAt: time.Now().Add(validFor).Unix(),
		Meta:      map[string]string{"seats": seats},
	}
	key, err := license.Issue(licenseApp, claims, testSigner)
	require.NoError(t, err)
	return key
}

func keyRow(key string) *db.WorkspaceLicense {
	return &db.WorkspaceLicense{WorkspaceID: "ws1", Key: key}
}

// trialRow is a hosted trial that ends in endsIn, a negative one has ended.
func trialRow(endsIn time.Duration) *db.WorkspaceLicense {
	return &db.WorkspaceLicense{WorkspaceID: "ws1", EndsAt: new(time.Now().Add(endsIn))}
}

func TestFromRow(t *testing.T) {
	tests := []struct {
		name     string
		sut      *Service
		row      *db.WorkspaceLicense
		wantPlan string
		wantKeep string
	}{
		{"self-hosted without a key", selfHosted, nil, PlanCommunity, PlanCommunity},
		{"hosted has no free plan", hosted, nil, PlanInactive, PlanInactive},
		{"a valid key", selfHosted, keyRow(issue(t, PlanEnterprise, time.Hour)), PlanEnterprise, PlanEnterprise},
		{"a key that never expires", hosted, keyRow(issue(t, PlanEnterprise, 0)), PlanEnterprise, PlanEnterprise},
		{
			"expired yesterday holds its data limits",
			selfHosted, keyRow(issue(t, PlanEnterprise, -day)),
			PlanCommunity, PlanEnterprise,
		},
		{
			"an expired hosted key holds them too",
			hosted, keyRow(issue(t, PlanEnterprise, -day)),
			PlanInactive, PlanEnterprise,
		},
		{
			"the hold ends after 30 days",
			selfHosted, keyRow(issue(t, PlanEnterprise, -(holdDays+1)*day)),
			PlanCommunity, PlanCommunity,
		},
		{"a key that does not verify", selfHosted, keyRow("NOKKU-AAAAA-BBBBB"), PlanCommunity, PlanCommunity},
		{"an unknown plan", hosted, keyRow(issue(t, "ultimate", time.Hour)), PlanInactive, PlanInactive},
		{"a running trial", hosted, trialRow(3 * day), PlanPro, PlanPro},
		{"a trial that ended holds its data limits", hosted, trialRow(-2 * day), PlanInactive, PlanPro},
		{
			"the hold of a trial ends after 30 days",
			hosted, trialRow(-(holdDays + 1) * day),
			PlanInactive, PlanInactive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := tt.sut.fromRow(tt.row)
			assert.Equal(t, tt.wantPlan, st.Plan.Name)
			assert.Equal(t, tt.wantKeep, st.Keep.Name)
			assert.Equal(t, tt.wantPlan != tt.wantKeep, st.HeldUntil != nil, "a hold has an end")
		})
	}
}

func TestFromRow_ExpiredKeyKeepsItsClaims(t *testing.T) {
	st := selfHosted.fromRow(keyRow(issue(t, PlanEnterprise, -time.Hour)))

	require.NotNil(t, st.License, "an expired key still carries the retention hold")
	assert.True(t, st.License.IsExpired())
	assert.EqualValues(t, 365, st.Keep.AuditRetentionDays, "an expired license must not purge data right away")
}

func TestFromRow_SeatsAreTheCap(t *testing.T) {
	st := hosted.fromRow(keyRow(issueSeats(t, PlanPro, time.Hour, "20")))
	assert.Equal(t, PlanPro, st.Plan.Name)
	assert.EqualValues(t, 20, st.Plan.SeatCap)

	expired := selfHosted.fromRow(keyRow(issueSeats(t, PlanPro, -day, "20")))
	assert.EqualValues(t, 5, expired.Plan.SeatCap, "an expired key drops to the Community cap")

	enterprise := selfHosted.fromRow(keyRow(issue(t, PlanEnterprise, time.Hour)))
	assert.Equal(t, unlimited, enterprise.Plan.SeatCap, "an Enterprise key without seats counts none")

	// A flat Enterprise price is bought once, its key says seats=1.
	st = hosted.fromRow(keyRow(issueSeats(t, PlanEnterprise, time.Hour, "1")))
	assert.Equal(t, PlanEnterprise, st.Plan.Name)
	assert.Equal(t, unlimited, st.Plan.SeatCap, "Enterprise ignores the seats of its key")
}

// The caps protect SaaS infrastructure, self-hosted disks are the customer's.
func TestFromRow_SelfHostedIsNeverCapped(t *testing.T) {
	for name, row := range map[string]*db.WorkspaceLicense{
		"community": nil,
		"licensed":  keyRow(issue(t, PlanEnterprise, time.Hour)),
		"expired":   keyRow(issue(t, PlanEnterprise, -day)),
	} {
		st := selfHosted.fromRow(row)
		assert.Equal(t, unlimited, st.Plan.ResourceCap, name)
		assert.Equal(t, unlimited, st.Plan.RecordingStorageBytes, name)
		assert.Equal(
			t,
			unlimited,
			st.Keep.RecordingStorageBytes,
			"%s: the purge jobs must see no storage cap either",
			name,
		)
	}

	st := hosted.fromRow(keyRow(issue(t, PlanEnterprise, time.Hour)))
	assert.NotEqual(t, unlimited, st.Plan.RecordingStorageBytes, "the hosted service caps storage")
}

func TestFromRow_Hold(t *testing.T) {
	st := selfHosted.fromRow(keyRow(issue(t, PlanEnterprise, time.Hour)))
	assert.Nil(t, st.HeldUntil, "a valid key holds nothing, it is in force")

	st = selfHosted.fromRow(keyRow(issue(t, PlanEnterprise, -day)))
	require.NotNil(t, st.HeldUntil)
	assert.WithinDuration(t, time.Now().Add((holdDays-1)*day), *st.HeldUntil, time.Minute)
}

func TestEnded(t *testing.T) {
	assert.Nil(t, Ended(trialRow(time.Hour)), "a running trial has not ended")
	assert.NotNil(t, Ended(trialRow(-time.Hour)))
	assert.Nil(t, Ended(keyRow("NOKKU-PERPETUAL")), "a key that never expires never ends")
}
