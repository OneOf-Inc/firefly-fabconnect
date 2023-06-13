package vault

import (
	"context"
	"fmt"
)

type Secret struct {
	c          *Client
	MountPoint string
}

func (c *Client) SecretWithMountPoint(MountPoint string) *Secret {
	return &Secret{
		c:          c,
		MountPoint: MountPoint,
	}
}

func (s *Secret) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := s.c.client.KVv2(s.MountPoint).Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("no secret was returned for path %s", path)
	}
	return secret.Data, nil
}

func (s *Secret) WriteSecret(path string, data map[string]interface{}) error {
	_, err := s.c.client.KVv2(s.MountPoint).Put(context.Background(), path, data)
	return err
}