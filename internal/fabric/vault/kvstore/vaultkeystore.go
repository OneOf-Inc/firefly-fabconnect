package kvstore

import (
	"fmt"

	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultKeyStore struct {
	path  string
	vault *vault.Vault
	db    kvstore.KVStore
}

func NewVaultKeyStore(path string, vault *vault.Vault, db kvstore.KVStore) *VaultKeyStore {
	return &VaultKeyStore{
		path:  path,
		vault: vault,
		db:    db,
	}
}

func (s *VaultKeyStore) Load(key interface{}) (interface{}, error) {
	keyId, err := s.db.Get(key.(string))
	if err != nil {
		return nil, err
	}

	// path := fmt.Sprintf("%s/%s", s.path, keyId)
	kv, err := s.vault.Transit().GetKey(string(keyId))
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
