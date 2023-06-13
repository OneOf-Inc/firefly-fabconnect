package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

type Client struct {
	client *api.Client
}

type Config struct {
	Address  string
	RoleID   string
	SecretID string
}

func NewClient(cfg *Config) (*Client, error) {
	client, err := api.NewClient(&api.Config{
		Address: cfg.Address,
	})
	if err != nil {
		return nil, err
	}

	appRoleAuth, err := auth.NewAppRoleAuth(cfg.RoleID, &auth.SecretID{FromString: cfg.SecretID})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}

	return &Client{client: client}, nil
}
