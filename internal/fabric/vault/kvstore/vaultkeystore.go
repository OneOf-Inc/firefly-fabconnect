package kvstore

import (
	"fmt"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultKeyStore struct {
	path  string
	vault *vault.Vault
}

func NewVaultKeyStore(path string, vault *vault.Vault) *VaultKeyStore {
	return &VaultKeyStore{
		path:  path,
		vault: vault,
	}
}

func (s *VaultKeyStore) Load(key interface{}) (interface{}, error) {

	// path := fmt.Sprintf("%s/%s", s.path, keyId)
	kv, err := s.vault.Transit().GetKey(string(key.(string)))
	if err != nil {
		return nil, err
	}
	return kv, nil
}

func (s *VaultKeyStore) Store(key interface{}, value interface{}) error {
	path := fmt.Sprintf("%s/%s", s.path, key.(string))
	err := s.vault.Transit().ImportKey(path, "ecdsa-p256", value.([]byte))
	if err != nil {
		return fmt.Errorf("failed to write secret to vault: %v", err)
	}
	return nil
}

func (s *VaultKeyStore) Delete(key interface{}) error {
	return fmt.Errorf("not implemented")
}
