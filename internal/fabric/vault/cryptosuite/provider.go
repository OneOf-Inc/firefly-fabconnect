package cryptosuite

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/api"
	signingMgr "github.com/hyperledger/fabric-sdk-go/pkg/fab/signingmgr"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/modlog"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

// ProviderFactory represents the default SDK provider factory.
type ProviderFactory struct {
	VaultConfig   *vault.Config
	TransitConfig *vault.TransitConfig
	SecretsConfig *vault.SecretsConfig
}

// NewProviderFactory returns the default SDK provider factory.
func NewProviderFactory(cfg *vault.Config, transitConfig *vault.TransitConfig, secretsConfig *vault.SecretsConfig) *ProviderFactory {
	return &ProviderFactory{
		VaultConfig:   cfg,
		TransitConfig: transitConfig,
		SecretsConfig: secretsConfig,
	}
}

// CreateCryptoSuiteProvider returns a new default implementation of BCCSP
func (f *ProviderFactory) CreateCryptoSuiteProvider(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	cryptoSuiteProvider, err := NewCryptoSuite(&CryptoSuiteVaultConfig{
		VaultConfig:   f.VaultConfig,
		TransitConfig: f.TransitConfig,
		SecretsConfig: f.SecretsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault crypto suite: %v", err)
	}
	return cryptoSuiteProvider, nil
}

// CreateSigningManager returns a new default implementation of signing manager
func (f *ProviderFactory) CreateSigningManager(cryptoProvider core.CryptoSuite) (core.SigningManager, error) {
	return signingMgr.New(cryptoProvider)
}

// CreateInfraProvider returns a new default implementation of fabric primitives
func (f *ProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}

// NewLoggerProvider returns a new default implementation of a logger backend
// This function is separated from the factory to allow logger creation first.
func NewLoggerProvider() api.LoggerProvider {
	return modlog.LoggerProvider()
}
