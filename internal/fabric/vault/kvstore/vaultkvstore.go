package kvstore

import (
	// "encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultKVStore struct {
	path  string
	vault *vault.Vault
}

func NewVaultKVStore(path string, vault *vault.Vault) *VaultKVStore {
	return &VaultKVStore{
		path:  path,
		vault: vault,
	}
}

func (s *VaultKVStore) Load(key interface{}) (interface{}, error) {
	path := fmt.Sprintf("%s/%s", s.path, key)
	kv, err := s.vault.Secret().ReadSecret(path)
	if err != nil {
		return nil, err
	}

	v := kv[key.(string)]
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault secret: %v", err)
	}

	return v, nil
}

func (s *VaultKVStore) Store(key interface{}, value interface{}) error {
	path := fmt.Sprintf("%s/%s", s.path, key.(string))
	v, ok := value.([]uint8)
	if !ok {
		return fmt.Errorf("value is not of proper type")
	}
	err := s.vault.Secret().WriteSecret(path, map[string]interface{}{key.(string): string(v)})
	if err != nil {
		return fmt.Errorf("failed to write secret to vault: %v", err)
	}
	return nil
}

func (s *VaultKVStore) Delete(key interface{}) error {
	return fmt.Errorf("not implemented")
}
