package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUntilTokenEnds(t *testing.T) {
	assert.Equal(t, time.Hour, untilTokenEnds(time.Hour, nil), "a token with no end cuts nothing")

	got := untilTokenEnds(120*time.Hour, new(time.Now().Add(5*time.Minute)))
	assert.LessOrEqual(t, got, 5*time.Minute, "the certificate outlives the token")
	assert.Greater(t, got, 4*time.Minute)

	got = untilTokenEnds(time.Hour, new(time.Now().Add(24*time.Hour)))
	assert.Equal(t, time.Hour, got, "a token that lives longer does not lengthen the certificate")

	got = untilTokenEnds(120*time.Hour, new(time.Now().Add(-time.Minute)))
	assert.Negative(t, got, "an expired token must leave nothing to sign for")
}
