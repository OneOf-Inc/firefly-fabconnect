package core

import (
	fabcore "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type ProviderFactory struct {
	vault *vault.Vault
	path  string
}

func NewProviderFactory(vault *vault.Vault, path string) *ProviderFactory {
	return &ProviderFactory{
		vault: vault,
		path:  path,
	}
}

func (p *ProviderFactory) CreateCryptoSuiteProvider(config fabcore.CryptoSuiteConfig) (fabcore.CryptoSuite, error) {
	return NewCryptoSuite(&CryptoSuiteVaultConfig{
		Vault: p.vault,
		Path:  p.path,
	})
}

func (p *ProviderFactory) CreateSigningManager(cryptoProvider fabcore.CryptoSuite) (fabcore.SigningManager, error) {
	return NewSigningManager(cryptoProvider, nil), nil
}

func (p *ProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}
