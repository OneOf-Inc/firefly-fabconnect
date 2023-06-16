package vault

import (
	"context"
	"os"

	"github.com/pkg/errors"

	"github.com/hashicorp/vault/api"
)

type SecretsConfig struct {
	MountPoint string
}

type Secret struct {
	c   *api.Client
	cfg *SecretsConfig
}

var (
	// ErrUserNotFound indicates the user was not found
	ErrUserNotFound = errors.New("user not found")
)

func WithSecretsConfigFromEnv() *SecretsConfig {
	return &SecretsConfig{MountPoint: os.Getenv("VAULT_SECRETS_MOUNT_POINT")}
}

func (v *Vault) Secret() *Secret {
	return &Secret{c: v.client, cfg: v.secretsCfg}
}

func (s *Secret) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := s.c.KVv2(s.cfg.MountPoint).Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	return secret.Data, nil
}

func (s *Secret) WriteSecret(path string, data map[string]interface{}) error {
	_, err := s.c.KVv2(s.cfg.MountPoint).Put(context.Background(), path, data)
	return err
}
