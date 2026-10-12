package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidSecret(t *testing.T) {
	require.NoError(t, ValidSecret("secret-a-0123456789-0123456789-01"))
	require.Error(t, ValidSecret(""))
	require.Error(t, ValidSecret("too-short"))
	require.Error(t, ValidSecret("CHANGE_ME_generate_with_openssl_rand"))
	assert.Error(t, ValidSecret("0123456789abcdefghijklmnopqrstuv"))
}
