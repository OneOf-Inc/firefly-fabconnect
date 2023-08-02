package vault

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

type Vault struct {
	client *api.Client

	transitCfg *TransitConfig
	secretsCfg *SecretsConfig

	RoleID   string
	SecretID string
}

type Config struct {
	Address       string
	RoleID        string
	SecretID      string
	TLSCaCert     string
	TLSClientCert string
	TLSClientKey  string
	*TransitConfig
	*SecretsConfig
}

func New(cfg *Config) (*Vault, error) {
	vaultConfig := &api.Config{
		Address: cfg.Address,
	}

	// verify if address is https
	parsedurl, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("unable to parse vault address: %w", err)
	}
	if parsedurl.Scheme == "https" {
		tlsCfg := api.TLSConfig{
			CACert:     cfg.TLSCaCert,
			ClientCert: cfg.TLSClientCert,
			ClientKey:  cfg.TLSClientKey,
		}
		if err := vaultConfig.ConfigureTLS(&tlsCfg); err != nil {
			return nil, fmt.Errorf("unable to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(vaultConfig)

	if err != nil {
		return nil, err
	}

	vault := &Vault{
		client:     client,
		transitCfg: cfg.TransitConfig,
		secretsCfg: cfg.SecretsConfig,
		RoleID:     cfg.RoleID,
		SecretID:   cfg.SecretID,
	}

	if err = vault.login(); err != nil {
		return nil, err
	}

	return vault, nil
}

func WithConfigFromEnv() *Config {
	cfg := &Config{
		Address:       os.Getenv("VAULT_ADDR"),
		RoleID:        os.Getenv("VAULT_ROLE_ID"),
		SecretID:      os.Getenv("VAULT_SECRET_ID"),
		TLSCaCert:     os.Getenv("VAULT_TLS_CA_CERT"),
		TLSClientCert: os.Getenv("VAULT_TLS_CLIENT_CERT"),
		TLSClientKey:  os.Getenv("VAULT_TLS_CLIENT_KEY"),
		TransitConfig: WithTransitConfigFromEnv(),
		SecretsConfig: WithSecretsConfigFromEnv(),
	}
	return cfg
}

func (v *Vault) login() error {
	appRoleAuth, err := auth.NewAppRoleAuth(v.RoleID, &auth.SecretID{FromString: v.SecretID})
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := v.client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}

	return nil
}
