// Copyright 2021 Kaleido
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/lookup"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/conf"
	"github.com/hyperledger/firefly-fabconnect/internal/errors"
	"github.com/hyperledger/firefly-fabconnect/internal/rest/identity"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
	log "github.com/sirupsen/logrus"

	vault_cs "github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/core"
	vault_msp "github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/msp"
)

// Instantiate an RPC client to interact with a Fabric network. based on the client configuration
// on gateway usage, it creates different types of client under the cover:
// - "useGatewayClient: true": returned RPCClient uses the client-side Gateway
// - "useGatewayClient: false": returned RPCClient uses a static network map described by the Connection Profile
// - "useGatewayServer: true": for Fabric 2.4 node only, the returned RPCClient utilizes the server-side gateway service
func RPCConnect(c conf.RPCConf, txTimeout int) (RPCClient, identity.IdentityClient, error) {
	configProvider := config.FromFile(c.ConfigPath)

	// userStore, err := newUserstore(configProvider)
	// if err != nil {
	// 	return nil, nil, errors.Errorf("User credentials store creation failed. %s", err)
	// }
	mspId, err := getMspIdFromConfig(configProvider)
	if err != nil {
		return nil, nil, err
	}
	certStorePath := fmt.Sprintf("%s/certs", mspId)
	vault, err := vault.New(vault.WithConfigFromEnv())
	if err != nil {
		return nil, nil, err
	}
	userStore, err := vault_msp.NewCertVaultUserStore(certStorePath)
	if err != nil {
		return nil, nil, errors.Errorf("User credentials store creation failed. %s", err)
	}
	identityClient, err := newIdentityClient(configProvider, userStore, vault, certStorePath)
	if err != nil {
		return nil, nil, err
	}

	cs, err := vault_cs.NewCryptoSuite(&vault_cs.CryptoSuiteVaultConfig{
		Vault: vault,
		Path:  certStorePath,
	})
	if err != nil {
		return nil, nil, errors.Errorf("Failed to create a new CryptoSuite instance. %s", err)
	}
	mspfactory := vault_msp.NewVaultMSPFactory(userStore, cs)

	adminCert, err := ioutil.ReadFile("/home/hossein/workspace/oneof/firefly-fabconnect/etc/firefly/organizations/peerOrganizations/org1.example.com/admin/bps01-cert.pem")
	if err != nil {
		return nil, nil, errors.Errorf("Failed to read admin certificate. %s", err)
	}
	adminKey, err := ioutil.ReadFile("/home/hossein/workspace/oneof/firefly-fabconnect/etc/firefly/organizations/peerOrganizations/org1.example.com/admin/bps01-key")
	if err != nil {
		return nil, nil, errors.Errorf("Failed to read admin key. %s", err)
	}
	// convert pem to ecdsa.PrivateKey
	adminCertBlock, _ := pem.Decode(adminCert)
	adminCertX509, err := x509.ParseCertificate(adminCertBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Errorf("Failed to parse admin certificate. %s", err)
	}

	adminKeyBlock, _ := pem.Decode(adminKey)
	if adminKeyBlock == nil || adminKeyBlock.Type != "PRIVATE KEY" {
		log.Fatal("Failed to decode PEM block containing EC private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(adminKeyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	_, err = cs.KeyImport(adminCertX509, nil)
	if err != nil {
		return nil, nil, errors.Errorf("Failed to import admin certificate. %s", err)
	}
	_, err = cs.KeyImport(key, nil)
	if err != nil {
		return nil, nil, errors.Errorf("Failed to import admin key. %s", err)
	}

	sdk, err := fabsdk.New(configProvider, fabsdk.WithMSPPkg(mspfactory), fabsdk.WithCorePkg(vault_cs.NewProviderFactory(vault, certStorePath)))
	if err != nil {
		return nil, nil, errors.Errorf("Failed to initialize a new SDK instance. %s", err)
	}
	ledgerClient := newLedgerClient(configProvider, sdk, identityClient)
	eventClient := newEventClient(configProvider, sdk, identityClient)
	var rpcClient RPCClient
	if !c.UseGatewayClient && !c.UseGatewayServer {
		rpcClient, err = newRPCClientFromCCP(configProvider, txTimeout, userStore, identityClient, ledgerClient, eventClient)
		if err != nil {
			return nil, nil, err
		}
		log.Info("Using static connection profile mode of the RPC client")
	} else if c.UseGatewayClient {
		rpcClient, err = newRPCClientWithClientSideGateway(configProvider, txTimeout, identityClient, ledgerClient, eventClient)
		if err != nil {
			return nil, nil, err
		}
		log.Info("Using client-side gateway mode of the RPC client")
	}
	return rpcClient, identityClient, nil
}

func getMspIdFromConfig(configProvider core.ConfigProvider) (string, error) {
	configBackend, err := configProvider()
	if err != nil {
		return "", errors.Errorf("Failed to load config: %s", err)
	}
	l := lookup.New(configBackend...)
	var client msp.ClientConfig
	l.UnmarshalKey("client", &client)
	organization := client.Organization
	var orgs map[string]map[string]interface{}
	l.UnmarshalKey("organizations", &orgs)
	mspId := orgs[organization]["mspid"]

	return mspId.(string), nil
}
