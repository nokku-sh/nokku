package kms

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/scaleway/tink-go-scwkms/integration/scwkms"
	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// kmsKEK returns the key encryption key behind uri. The key never leaves the
// KMS, every wrap and unwrap is a call to it.
func (t *TinkEncryptor) kmsKEK(uri string) (tink.AEAD, error) {
	provider, _, _ := strings.Cut(uri, "://")
	slog.Debug("setting up kms client", "provider", provider)

	var client registry.KMSClient
	var err error
	switch provider {
	case "hcvault":
		if t.VaultToken == "" {
			return nil, errors.New("VAULT_TOKEN required for hcvault")
		}
		hostPort, _, _ := strings.Cut(strings.TrimPrefix(uri, "hcvault://"), "/")
		scheme := "https://"
		if t.VaultSkipVerify {
			scheme = "http://"
		}
		vaultClient, vaultErr := api.NewClient(&api.Config{
			Address:    scheme + hostPort,
			HttpClient: api.DefaultConfig().HttpClient,
		})
		if vaultErr != nil {
			return nil, vaultErr
		}
		vaultClient.SetToken(t.VaultToken)
		client, err = hcvault.NewClientWithAEADOptions("hcvault://"+hostPort, vaultClient.Logical())
	case "scw-kms":
		region, _, ok := strings.Cut(strings.TrimPrefix(uri, "scw-kms://regions/"), "/keys/")
		if !ok || region == "" {
			return nil, errors.New("invalid scw-kms URI")
		}
		client, err = scwkms.NewClientWithOptions("scw-kms://regions/"+region+"/keys/", scw.WithEnv())
	default:
		return nil, fmt.Errorf("unsupported KMS provider %q, use hcvault:// or scw-kms://", provider)
	}
	if err != nil {
		return nil, err
	}
	return client.GetAEAD(uri)
}
