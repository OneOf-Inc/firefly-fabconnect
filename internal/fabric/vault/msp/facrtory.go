package msp

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	fabmsp "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultMSPFactory struct {
	vaultUserStore *CertVaultUserStore
	cryptoProvider core.CryptoSuite
	db             kvstore.KVStore
}

// NewVaultMSPFactory creates a custom MSPFactory
func NewVaultMSPFactory(vaultUserStore *CertVaultUserStore, cryptoProvider core.CryptoSuite, db kvstore.KVStore) *VaultMSPFactory {
	return &VaultMSPFactory{vaultUserStore: vaultUserStore, cryptoProvider: cryptoProvider, db: db}
}

// CreateUserStore creates UserStore
func (f *VaultMSPFactory) CreateUserStore(config fabmsp.IdentityConfig) (fabmsp.UserStore, error) {
	return f.vaultUserStore, nil
}

// CreateIdentityManagerProvider creates an IdentityManager provider
func (f *VaultMSPFactory) CreateIdentityManagerProvider(endpointConfig fab.EndpointConfig, cryptoProvider core.CryptoSuite, userStore fabmsp.UserStore) (fabmsp.IdentityManagerProvider, error) {
	vault, err := vault.New(vault.WithConfigFromEnv())
	if err != nil {
		return nil, err
	}

	return NewMspProvider(endpointConfig, f.cryptoProvider, f.vaultUserStore, vault, f.db)
}
