package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
)

type SecretsConfig struct {
	MountPoint string
}

type Secret struct {
	v    *Vault
	c    *api.Client
	cfg  *SecretsConfig
}

func WithSecretsConfigFromEnv() *SecretsConfig {
	return &SecretsConfig{MountPoint: os.Getenv("VAULT_SECRETS_MOUNT_POINT")}
}

func (v *Vault) Secret() *Secret {
	return &Secret{c: v.client, v: v, cfg: v.secretsCfg}
}

func (s *Secret) ReadSecret(path string) (map[string]interface{}, error) {
	if err := s.v.login(); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %v", err)
	}

	secret, err := s.c.KVv2(s.cfg.MountPoint).Get(context.Background(), path)
	if err != nil {
		// error message contains "secret not found"
		if strings.Contains(err.Error(), "secret not found") {
			return nil, msp.ErrUserNotFound
		}
		return nil, err
	}
	if secret == nil {
		return nil, msp.ErrUserNotFound
	}
	return secret.Data, nil
}

func (s *Secret) WriteSecret(path string, data map[string]interface{}) error {
	if err := s.v.login(); err != nil {
		return fmt.Errorf("failed to authenticate: %v", err)
	}

	_, err := s.c.KVv2(s.cfg.MountPoint).Put(context.Background(), path, data)
	return err
}
