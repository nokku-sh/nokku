package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServiceAccountTTL(t *testing.T) {
	assert.Equal(t, time.Hour, serviceAccountTTL(120*time.Hour, nil), "a workspace lifetime of days gets the cap")
	assert.Equal(t, 10*time.Minute, serviceAccountTTL(10*time.Minute, nil), "a workspace lifetime under the cap wins")
}

func TestServiceAccountTTLEndsWithTheToken(t *testing.T) {
	got := serviceAccountTTL(120*time.Hour, new(time.Now().Add(5*time.Minute)))
	assert.LessOrEqual(t, got, 5*time.Minute, "the certificate outlives the token")
	assert.Greater(t, got, 4*time.Minute)

	got = serviceAccountTTL(120*time.Hour, new(time.Now().Add(24*time.Hour)))
	assert.Equal(t, time.Hour, got, "a token that lives longer does not lift the cap")

	got = serviceAccountTTL(120*time.Hour, new(time.Now().Add(-time.Minute)))
	assert.Negative(t, got, "an expired token must leave nothing to sign for")
}
