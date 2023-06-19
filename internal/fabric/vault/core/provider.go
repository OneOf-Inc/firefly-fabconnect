package core

import (
	fabcore "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"

	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type ProviderFactory struct {
	db kvstore.KVStore
}

func NewProviderFactory(db kvstore.KVStore) *ProviderFactory {
	return &ProviderFactory{
		db: db,
	}
}

func (p *ProviderFactory) CreateCryptoSuiteProvider(config fabcore.CryptoSuiteConfig) (fabcore.CryptoSuite, error) {
	return NewCryptoSuite(&CryptoSuiteVaultConfig{
		VaultConfig: vault.WithConfigFromEnv(),
		DB:          p.db,
	})
}

func (p *ProviderFactory) CreateSigningManager(cryptoProvider fabcore.CryptoSuite) (fabcore.SigningManager, error) {
	return NewSigningManager(cryptoProvider, nil), nil
}

func (p *ProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}
