package api

import (
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
)

// Refused before anything is stored. The config has no iam, getting that far would panic.
func TestHostedSSOProviderNeedsTLS(t *testing.T) {
	svc := &ssoService{cfg: &config.Config{SaaS: true}}
	_, err := svc.PutSSOProvider(t.Context(), &nokkuv1.PutSSOProviderRequest{
		ProviderId: new("lab"), Name: new("Lab"), IssuerUrl: new("http://idp.example/realms/lab"),
		ClientId: new("nokku"), ClientSecret: new("s3cret"),
	})
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "got %v", err)
}
