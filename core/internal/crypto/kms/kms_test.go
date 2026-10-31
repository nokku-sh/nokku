package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Neither a KMS nor a secret leaves nothing to wrap the keyset with. The database is not touched before that.
func TestNewNeedsAKMSOrASecret(t *testing.T) {
	t.Setenv("KMS_URI", "")
	t.Setenv("NOKKU_SECRET", "")
	_, err := New(t.Context(), nil, false)
	assert.ErrorContains(t, err, "KMS_URI or NOKKU_SECRET")
}

// Hosted refuses a secret before it touches the database, so a refused boot leaves no keyset to move later.
func TestHostedServiceNeedsAKMS(t *testing.T) {
	t.Setenv("KMS_URI", "")
	t.Setenv("NOKKU_SECRET", "secret-a-0123456789-0123456789-01")
	_, err := New(t.Context(), nil, true)
	assert.ErrorContains(t, err, "NOKKU_SAAS needs KMS_URI")
}

func TestValidSecret(t *testing.T) {
	require.NoError(t, validSecret("secret-a-0123456789-0123456789-01"))
	require.Error(t, validSecret(""))
	require.Error(t, validSecret("too-short"))
	require.Error(t, validSecret("CHANGE_ME_generate_with_openssl_rand"))
	assert.Error(t, validSecret("0123456789abcdefghijklmnopqrstuv"))
}
