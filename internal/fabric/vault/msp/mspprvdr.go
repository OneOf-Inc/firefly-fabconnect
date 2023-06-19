/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
	"github.com/pkg/errors"
)

// MSPProvider provides the default implementation of MSP
type MSPProvider struct {
	userStore       msp.UserStore
	identityManager map[string]msp.IdentityManager
}

// New creates a MSP context provider
func NewMspProvider(endpointConfig fab.EndpointConfig, cryptoSuite core.CryptoSuite, userStore msp.UserStore, vault *vault.Vault, db kvstore.KVStore) (*MSPProvider, error) {

	identityManager := make(map[string]msp.IdentityManager)
	netConfig := endpointConfig.NetworkConfig()
	for orgName := range netConfig.Organizations {
		mgr, err := NewIdentityManager(orgName, userStore, cryptoSuite, endpointConfig, vault, db)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to initialize identity manager for organization: %s", orgName)
		}
		identityManager[orgName] = mgr
	}

	mspProvider := MSPProvider{
		userStore:       userStore,
		identityManager: identityManager,
	}

	return &mspProvider, nil
}

// IdentityManager returns the organization's identity manager
func (p *MSPProvider) IdentityManager(orgName string) (msp.IdentityManager, bool) {
	im, ok := p.identityManager[strings.ToLower(orgName)]
	if !ok {
		return nil, false
	}
	return im, true
}
