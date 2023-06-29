package msp

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"

	"github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

func NewVaultKeyStore(path string, vault *vault.Vault) (core.KVStore, error) {
	return kvstore.NewVaultKeyStore(fmt.Sprintf("certs/%s", path), vault), nil
}