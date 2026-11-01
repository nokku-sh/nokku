package kms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/scaleway/tink-go-scwkms/integration/scwkms"
	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	vaultTokenTimeout = 15 * time.Second
	vaultTokenRetry   = time.Minute
	// Longest gap between renewals, so a token outlives a short Vault outage.
	vaultTokenCheck = time.Hour
)

// The key encryption key never leaves the KMS, every wrap is a call to it.
func (k *Keyset) kmsKEK(uri string) (tink.AEAD, error) {
	provider, _, _ := strings.Cut(uri, "://")

	var client registry.KMSClient
	var err error
	switch provider {
	case "hcvault":
		hostPort, _, _ := strings.Cut(strings.TrimPrefix(uri, "hcvault://"), "/")
		vault, vaultErr := k.vaultClient(hostPort)
		if vaultErr != nil {
			return nil, vaultErr
		}
		client, err = hcvault.NewClientWithAEADOptions("hcvault://"+hostPort, vault.Logical())
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

func (k *Keyset) vaultClient(hostPort string) (*api.Client, error) {
	if k.VaultToken == "" {
		return nil, errors.New("VAULT_TOKEN required for hcvault")
	}
	// Brings timeout and retries. VAULT_SKIP_VERIFY turns off the TLS check.
	cfg := api.DefaultConfig()
	cfg.Address = "https://" + hostPort
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(k.VaultToken)
	k.vault = client
	return client, nil
}

// VaultTokenLoop keeps VAULT_TOKEN alive, an ended one can't open the keyset.
func (k *Keyset) VaultTokenLoop(ctx context.Context) {
	if k.vault == nil {
		return
	}
	for {
		next, err := k.renewVaultToken(ctx)
		if err != nil {
			next = vaultTokenRetry
			slog.Error("VAULT_TOKEN was not renewed, once it ends the core can't start", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// A token that isn't periodic hits Vault's limit, so it warns every time.
func (k *Keyset) renewVaultToken(ctx context.Context) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultTokenTimeout)
	defer cancel()
	tokens := k.vault.Auth().Token()
	self, err := tokens.LookupSelfWithContext(ctx)
	if err != nil {
		return 0, err
	}
	ttl, err := self.TokenTTL()
	if err != nil {
		return 0, err
	}
	// A root token never ends.
	if ttl == 0 {
		return vaultTokenCheck, nil
	}
	renewable, err := self.TokenIsRenewable()
	if err != nil {
		return 0, err
	}
	if renewable {
		renewed, err := tokens.RenewSelfWithContext(ctx, 0)
		if err != nil {
			return 0, err
		}
		if ttl, err = renewed.TokenTTL(); err != nil {
			return 0, err
		}
	}
	if self.Data["period"] == nil {
		slog.Warn("VAULT_TOKEN is not periodic, the core can't start once it ends", "ends_in", ttl)
	}
	return min(ttl/2, vaultTokenCheck), nil
}
