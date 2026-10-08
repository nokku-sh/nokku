package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/internal/db"
)

func TestServiceAccountTTL(t *testing.T) {
	long := &db.SSHCA{UserDefaultTtl: 120 * time.Hour, UserMaxTtl: 168 * time.Hour}
	short := &db.SSHCA{UserDefaultTtl: 10 * time.Minute, UserMaxTtl: 8 * time.Hour}

	tests := []struct {
		name string
		ca   *db.SSHCA
		ttl  time.Duration
		want time.Duration
	}{
		{"nothing asked gets the cap, not the CA default of days", long, 0, time.Hour},
		{"more than the cap gets the cap", long, 48 * time.Hour, time.Hour},
		{"less than the cap is kept", long, 10 * time.Minute, 10 * time.Minute},
		{"a CA default under the cap wins", short, 0, 10 * time.Minute},
		{"more than the CA allows falls back to its default", short, 9 * time.Hour, 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, serviceAccountTTL(tt.ca, tt.ttl, nil))
		})
	}
}

func TestServiceAccountTTLEndsWithTheToken(t *testing.T) {
	ca := &db.SSHCA{UserDefaultTtl: 120 * time.Hour, UserMaxTtl: 168 * time.Hour}

	got := serviceAccountTTL(ca, 0, new(time.Now().Add(5*time.Minute)))
	assert.LessOrEqual(t, got, 5*time.Minute, "the certificate outlives the token")
	assert.Greater(t, got, 4*time.Minute)

	got = serviceAccountTTL(ca, 0, new(time.Now().Add(24*time.Hour)))
	assert.Equal(t, time.Hour, got, "a token that lives longer does not lift the cap")

	got = serviceAccountTTL(ca, 0, new(time.Now().Add(-time.Minute)))
	assert.Negative(t, got, "an expired token must leave nothing to sign for")
}
