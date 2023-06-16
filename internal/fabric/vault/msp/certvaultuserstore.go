package msp

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"

	"github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)


type CertVaultUserStore struct {
	store *kvstore.VaultKVStore
}

// NewCertFileUserStore creates a new instance of CertFileUserStore
func NewCertVaultUserStore(path string) (*CertVaultUserStore, error) {
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}

	v, err := vault.New(vault.WithConfigFromEnv())
	if err != nil {
		return nil, fmt.Errorf("vault client creation failed: %v", err)
	}

	store := kvstore.NewVaultKVStore(path, v)
	if err != nil {
		return nil, fmt.Errorf("user store creation failed: %v", err)
	}

	return &CertVaultUserStore{store}, nil
}

// Load returns the User stored in the store for a key.
func (s *CertVaultUserStore) Load(key msp.IdentityIdentifier) (*msp.UserData, error) {
	cert, err := s.store.Load(storeKeyFromUserIdentifier(key))
	if err != nil {
		return nil, fmt.Errorf("user load failed: %v", err)
	}

	certBytes, ok := cert.([]byte)
	if !ok {
		return nil, fmt.Errorf("user is not of proper type")
	}

	userData := &msp.UserData{
		MSPID:                 key.MSPID,
		ID:                    key.ID,
		EnrollmentCertificate: certBytes,
	}
	return userData, nil
}

// Store stores a User into store
func (s *CertVaultUserStore) Store(user *msp.UserData) error {
	key := storeKeyFromUserIdentifier(msp.IdentityIdentifier{ID: user.ID, MSPID: user.MSPID})
	return s.store.Store(key, user.EnrollmentCertificate)
}

// Delete deletes a User from store
func (s *CertVaultUserStore) Delete(key msp.IdentityIdentifier) error {
	return fmt.Errorf("not implemented")
}

func storeKeyFromUserIdentifier(key msp.IdentityIdentifier) string {
	return key.ID // + "@" + key.MSPID + "-cert.pem"
}