package config

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/lookup"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp"
)

type WalletConfig struct {
	Addr          string
	MspId         string
	UserStorePath string
}

func NewWalletConfig(addr string, c ...core.ConfigBackend) WalletConfig {
	l := lookup.New(c...)

	var client msp.ClientConfig
	l.UnmarshalKey("client", &client)
	credntialStore := client.CredentialStore.Path
	organization := client.Organization

	var orgs map[string]map[string]interface{}
	l.UnmarshalKey("organizations", &orgs)
	mspId := orgs[organization]["mspid"]

	return WalletConfig{
		Addr:          addr,
		MspId:         mspId.(string),
		UserStorePath: credntialStore,
	}
}
