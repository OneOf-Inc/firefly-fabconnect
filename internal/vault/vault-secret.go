package vault

import (
	"context"
	"fmt"
	"os"
)

type SecretsConfig struct {
	MountPoint string
}

type Secret struct {
	c   *Client
	cfg *SecretsConfig
}

func WithSecretsConfigFromEnv() *SecretsConfig {
	return &SecretsConfig{MountPoint: os.Getenv("VAULT_SECRETS_MOUNT_POINT")}
}

func (c *Client) SecretWithConfig(cfg *SecretsConfig) *Secret {
	return &Secret{c, cfg}
}

func (s *Secret) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := s.c.client.KVv2(s.cfg.MountPoint).Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret was returned for path %s", path)
	}
	return secret.Data, nil
}

func (s *Secret) WriteSecret(path string, data map[string]interface{}) error {
	_, err := s.c.client.KVv2(s.cfg.MountPoint).Put(context.Background(), path, data)
	return err
}
