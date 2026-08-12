package kms

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/scaleway/tink-go-scwkms/integration/scwkms"
	"github.com/tink-crypto/tink-go-awskms/v3/integration/awskms"
	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
)

// setupClient creates the KMS client for the configured URI scheme and
// caches the KEK AEAD used to wrap/unwrap the stored keyset.
func (t *TinkEncryptor) setupClient(ctx context.Context) (err error) {
	slog.Debug("setting up kms client", "provider", kmsProvider(t.KMSURI))
	switch {
	case strings.HasPrefix(t.KMSURI, "aws-kms://"):
		t.client, err = awskms.NewClientWithOptions(ctx, t.KMSURI)
	// TODO: gcp-kms support disabled until upstream genproto is fixed
	case strings.HasPrefix(t.KMSURI, "hcvault://"):
		if t.VaultToken == "" {
			return fmt.Errorf("VAULT_TOKEN required for hcvault")
		}
		uriWithoutScheme := strings.TrimPrefix(t.KMSURI, "hcvault://")
		hostPort, _, _ := strings.Cut(uriWithoutScheme, "/")

		scheme := "https://"
		if t.VaultSkipVerify {
			scheme = "http://"
		}

		vaultClient, err := api.NewClient(&api.Config{
			Address:    scheme + hostPort,
			HttpClient: api.DefaultConfig().HttpClient,
		})
		if err != nil {
			return err
		}
		vaultClient.SetToken(t.VaultToken)
		uriPrefix := "hcvault://" + hostPort
		t.client, err = hcvault.NewClientWithAEADOptions(uriPrefix, vaultClient.Logical())
		if err != nil {
			return err
		}
	case strings.HasPrefix(t.KMSURI, "scw-kms://"):
		rest := strings.TrimPrefix(t.KMSURI, "scw-kms://regions/")
		region, _, ok := strings.Cut(rest, "/keys/")
		if !ok || region == "" {
			return fmt.Errorf("invalid scw-kms URI")
		}

		prefix := "scw-kms://regions/" + region + "/keys/"
		t.client, err = scwkms.NewClientWithOptions(prefix, scw.WithEnv())
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported KMS provider")
	}
	if err != nil {
		return err
	}

	t.kekAEAD, err = t.client.GetAEAD(t.KMSURI)
	return err
}

func kmsProvider(uri string) string {
	provider, _, ok := strings.Cut(uri, "://")
	if !ok || provider == "" {
		return "unknown"
	}
	return provider
}
