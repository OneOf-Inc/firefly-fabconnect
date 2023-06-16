package msp

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"

	dbkvstore "github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

func NewVaultKeyStore(path string, vault *vault.Vault, db dbkvstore.KVStore) (core.KVStore, error) {
	return kvstore.NewVaultKeyStore(fmt.Sprintf("certs/%s", path), vault, db), nil
}