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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	fabcontext "github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	fabImpl "github.com/hyperledger/fabric-sdk-go/pkg/fab"
	mspImpl "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	mspApi "github.com/hyperledger/fabric-sdk-go/pkg/msp/api"
	"github.com/hyperledger/firefly-fabconnect/internal/errors"
	"github.com/hyperledger/firefly-fabconnect/internal/fabric/dep"
	"github.com/hyperledger/firefly-fabconnect/internal/obp"
	"github.com/hyperledger/firefly-fabconnect/internal/rest/identity"
	restutil "github.com/hyperledger/firefly-fabconnect/internal/rest/utils"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	vault_cs "github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/core"
	vault_msp "github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type identityManagerProvider struct {
	identityManager msp.IdentityManager
}

// IdentityManager returns the organization's identity manager
func (p *identityManagerProvider) IdentityManager(orgName string) (msp.IdentityManager, bool) {
	return p.identityManager, true
}

type idClientWrapper struct {
	identityConfig msp.IdentityConfig
	identityMgr    msp.IdentityManager
	caClient       dep.CAClient
	listeners      []SignerUpdateListener
}

func newIdentityClient(configProvider core.ConfigProvider, userStore msp.UserStore, vault *vault.Vault, path string) (*idClientWrapper, error) {
	configBackend, _ := configProvider()
	cryptoConfig := cryptosuite.ConfigFromBackend(configBackend...)

	cs, err := vault_cs.NewCryptoSuite(&vault_cs.CryptoSuiteVaultConfig{
		Vault: vault,
		Path:  path,
	})
	if err != nil {
		return nil, errors.Errorf("Failed to get suite by config: %s", err)
	}

	endpointConfig, err := fabImpl.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, errors.Errorf("Failed to read config: %s", err)
	}
	identityConfig, err := mspImpl.ConfigFromBackend(configBackend...)
	if err != nil {
		return nil, errors.Errorf("Failed to load identity configurations: %s", err)
	}
	clientConfig := identityConfig.Client()
	if clientConfig.CredentialStore.Path == "" {
		return nil, errors.Errorf("User credentials store path is empty")
	}
	// mgr, err := mspImpl.NewIdentityManager(clientConfig.Organization, userStore, cs, endpointConfig)

	mgr, err := vault_msp.NewIdentityManager(clientConfig.Organization, userStore, cs, endpointConfig, vault)
	if err != nil {
		return nil, errors.Errorf("Identity manager creation failed. %s", err)
	}

	identityManagerProvider := &identityManagerProvider{
		identityManager: mgr,
	}
	ctxProvider := fabcontext.NewProvider(
		fabcontext.WithIdentityManagerProvider(identityManagerProvider),
		fabcontext.WithUserStore(userStore),
		fabcontext.WithCryptoSuite(cs),
		fabcontext.WithCryptoSuiteConfig(cryptoConfig),
		fabcontext.WithEndpointConfig(endpointConfig),
		fabcontext.WithIdentityConfig(identityConfig),
	)
	ctx := &fabcontext.Client{
		Providers: ctxProvider,
	}
	caClient, err := mspImpl.NewCAClient(clientConfig.Organization, ctx)
	if err != nil {
		return nil, errors.Errorf("CA Client creation failed. %s", err)
	}
	var listeners []SignerUpdateListener
	idc := &idClientWrapper{
		identityConfig: identityConfig,
		identityMgr:    mgr,
		caClient:       caClient,
		listeners:      listeners,
	}
	return idc, nil
}

func (w *idClientWrapper) GetSigningIdentity(name string) (msp.SigningIdentity, error) {
	return w.identityMgr.GetSigningIdentity(name)
}

func (w *idClientWrapper) GetClientOrg() string {
	return w.identityConfig.Client().Organization
}

// the rpcWrapper is also an implementation of the interface internal/rest/idenity/IdentityClient
func (w *idClientWrapper) Register(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.RegisterResponse, *restutil.RestError) {
	regreq := identity.Identity{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&regreq)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to decode JSON payload: %s", err), 400)
	}
	if regreq.Name == "" {
		return nil, restutil.NewRestError(`missing required parameter "name"`, 400)
	}
	if regreq.Type == "" {
		regreq.Type = "client"
	}

	// register user to OBP IDCS and add to USER_CA group
	oracle := obp.New(obp.OBPConfigFromEnv())
	user, err := oracle.CreateValidatedUser(&obp.UserData{
		Username:   regreq.Name,
		FamilyName: regreq.Email,
		GivenName:  regreq.Email,
		MiddleName: regreq.Email,
		Email:      regreq.Email,
	})
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to register user %s to OBP IDCS: %s", regreq.Name, err), 500)
	}

	rr := &mspApi.RegistrationRequest{
		Name:           regreq.Name,
		Type:           regreq.Type,
		MaxEnrollments: regreq.MaxEnrollments,
		Affiliation:    regreq.Affiliation,
		CAName:         regreq.CAName,
		Secret:         user.Password,
	}
	if regreq.Attributes != nil {
		rr.Attributes = []mspApi.Attribute{}
		for key, value := range regreq.Attributes {
			rr.Attributes = append(rr.Attributes, mspApi.Attribute{Name: key, Value: value})
		}
	}

	secret, err := w.caClient.Register(rr)
	if err != nil {
		log.Errorf("Failed to register user %s. %s", regreq.Name, err)
		return nil, restutil.NewRestError(err.Error())
	}

	if err = w.identityMgr.(*vault_msp.IdentityManager).StoreSecret(regreq.Name, []byte(secret)); err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to store secret for user %s: %s", regreq.Name, err), 500)
	}

	result := identity.RegisterResponse{
		Name:   rr.Name,
		Secret: "***",
	}
	return &result, nil
}

func (w *idClientWrapper) Modify(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.RegisterResponse, *restutil.RestError) {
	username := params.ByName("username")
	regreq := identity.Identity{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&regreq)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to decode JSON payload: %s", err), 400)
	}

	secret, err := w.identityMgr.(*vault_msp.IdentityManager).GetSecret(username)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get secret for user %s: %s", username, err), 500)
	}

	rr := &mspApi.IdentityRequest{
		ID:             username,
		Type:           regreq.Type,
		MaxEnrollments: regreq.MaxEnrollments,
		Affiliation:    regreq.Affiliation,
		CAName:         regreq.CAName,
		Secret:         string(secret),
	}
	if regreq.Attributes != nil {
		rr.Attributes = []mspApi.Attribute{}
		for key, value := range regreq.Attributes {
			rr.Attributes = append(rr.Attributes, mspApi.Attribute{Name: key, Value: value})
		}
	}

	_, err = w.caClient.ModifyIdentity(rr)
	if err != nil {
		log.Errorf("Failed to modify user %s. %s", regreq.Name, err)
		return nil, restutil.NewRestError(err.Error())
	}

	result := identity.RegisterResponse{
		Name: rr.ID,
	}
	return &result, nil
}

func (w *idClientWrapper) Enroll(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.IdentityResponse, *restutil.RestError) {
	username := params.ByName("username")
	enreq := identity.EnrollRequest{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&enreq)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to decode JSON payload: %s", err), 400)
	}
	// if enreq.Secret == "" {
	// 	return nil, restutil.NewRestError(`missing required parameter "secret"`, 400)
	// }

	secret, err := w.identityMgr.(*vault_msp.IdentityManager).GetSecret(username)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get secret for user %s: %s", username, err), 500)
	}

	input := mspApi.EnrollmentRequest{
		Name:    username,
		Secret:  string(secret),
		CAName:  enreq.CAName,
		Profile: enreq.Profile,
	}
	if enreq.AttrReqs != nil {
		input.AttrReqs = []*mspApi.AttributeRequest{}
		for attr, optional := range enreq.AttrReqs {
			input.AttrReqs = append(input.AttrReqs, &mspApi.AttributeRequest{Name: attr, Optional: optional})
		}
	}

	err = w.caClient.Enroll(&input)
	if err != nil {
		log.Errorf("Failed to enroll user %s. %s", enreq.Name, err)
		return nil, restutil.NewRestError(err.Error())
	}

	result := identity.IdentityResponse{
		Name:    enreq.Name,
		Success: true,
	}

	w.notifySignerUpdate(username)
	return &result, nil
}

func (w *idClientWrapper) Reenroll(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.IdentityResponse, *restutil.RestError) {
	username := params.ByName("username")
	enreq := identity.EnrollRequest{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&enreq)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to decode JSON payload: %s", err), 400)
	}

	input := mspApi.ReenrollmentRequest{
		Name:    username,
		CAName:  enreq.CAName,
		Profile: enreq.Profile,
	}
	if enreq.AttrReqs != nil {
		input.AttrReqs = []*mspApi.AttributeRequest{}
		for attr, optional := range enreq.AttrReqs {
			input.AttrReqs = append(input.AttrReqs, &mspApi.AttributeRequest{Name: attr, Optional: optional})
		}
	}

	err = w.caClient.Reenroll(&input)
	if err != nil {
		log.Errorf("Failed to re-enroll user %s. %s", username, err)
		return nil, restutil.NewRestError(err.Error())
	}

	result := identity.IdentityResponse{
		Name:    username,
		Success: true,
	}

	w.notifySignerUpdate(username)
	return &result, nil
}

func (w *idClientWrapper) Revoke(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.RevokeResponse, *restutil.RestError) {
	username := params.ByName("username")
	enreq := identity.RevokeRequest{}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&enreq)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to decode JSON payload: %s", err), 400)
	}

	id, err := w.identityMgr.GetSigningIdentity(username)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get signing identity for user %s: %s", username, err), 500)
	}
	cert := id.EnrollmentCertificate()
	block, _ := pem.Decode(cert)
	if block == nil {
		log.Fatal("Failed to decode PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to parse certificate for user %s: %s", username, err), 500)
	}
	aki := hex.EncodeToString(c.AuthorityKeyId)
	serialNumber := hex.EncodeToString(c.SerialNumber.Bytes())

	input := mspApi.RevocationRequest{
		Name:   username,
		CAName: enreq.CAName,
		Reason: enreq.Reason,
		GenCRL: enreq.GenCRL,
		Serial: serialNumber,
		AKI:    aki,
	}

	response, err := w.caClient.Revoke(&input)
	if err != nil {
		log.Errorf("Failed to revoke certificate for user %s. %s", enreq.Name, err)
		return nil, restutil.NewRestError(err.Error())
	}

	result := identity.RevokeResponse{
		CRL: response.CRL,
	}
	if len(response.RevokedCerts) > 0 {
		result.RevokedCerts = []map[string]string{}
		for _, cert := range response.RevokedCerts {
			entry := map[string]string{}
			entry["aki"] = cert.AKI
			entry["serial"] = cert.Serial
			result.RevokedCerts = append(result.RevokedCerts, entry)
		}
	}
	return &result, nil
}

type CaListIdentitiesResultResponse struct {
	Identities []*mspApi.IdentityResponse `json:"identities"`
}
type CaListIdentitiesResponse struct {
	Result CaListIdentitiesResultResponse `json:"result"`
}

type CaGetIdentityResponse struct {
	Result *mspApi.IdentityResponse `json:"result"`
}

func (w *idClientWrapper) List(res http.ResponseWriter, req *http.Request, params httprouter.Params) ([]*identity.Identity, *restutil.RestError) {

	registrar, err := w.GetSigningIdentity("jmagly@oneof.com")
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get signing identity for user %s: %s", "jmagly", err), 500)
	}

	oracle := obp.New(obp.OBPConfigFromEnv())
	d, err := oracle.GetIdentities(registrar.EnrollmentCertificate(), registrar.Sign)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get identities: %s", err), 500)
	}

	var resp CaListIdentitiesResponse
	if err := json.Unmarshal(d, &resp); err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to unmarshal response: %s", err), 500)
	}

	ret := make([]*identity.Identity, len(resp.Result.Identities))
	for i, v := range resp.Result.Identities {
		newId := identity.Identity{}
		newId.Name = v.ID
		newId.MaxEnrollments = v.MaxEnrollments
		newId.CAName = v.CAName
		newId.Type = v.Type
		newId.Affiliation = v.Affiliation
		if len(v.Attributes) > 0 {
			newId.Attributes = make(map[string]string, len(v.Attributes))
			for _, attr := range v.Attributes {
				newId.Attributes[attr.Name] = attr.Value
			}
		}
		ret[i] = &newId
	}
	return ret, nil
}

func (w *idClientWrapper) Get(res http.ResponseWriter, req *http.Request, params httprouter.Params) (*identity.Identity, *restutil.RestError) {
	username := params.ByName("username")

	registrar, err := w.GetSigningIdentity("jmagly@oneof.com")
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get signing identity for user %s: %s", "jmagly", err), 500)
	}

	oracle := obp.New(obp.OBPConfigFromEnv())
	d, err := oracle.GetIdentity(username, registrar.EnrollmentCertificate(), registrar.Sign)
	if err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to get identities: %s", err), 500)
	}
	fmt.Printf("response: %s\n", string(d))

	var resp CaGetIdentityResponse
	if err := json.Unmarshal(d, &resp); err != nil {
		return nil, restutil.NewRestError(fmt.Sprintf("failed to unmarshal response: %s", err), 500)
	}

	newId := identity.Identity{}
	newId.Name = resp.Result.ID
	newId.MaxEnrollments = resp.Result.MaxEnrollments
	newId.CAName = resp.Result.CAName
	newId.Type = resp.Result.Type
	newId.Affiliation = resp.Result.Affiliation
	if len(resp.Result.Attributes) > 0 {
		newId.Attributes = make(map[string]string, len(resp.Result.Attributes))
		for _, attr := range resp.Result.Attributes {
			newId.Attributes[attr.Name] = attr.Value
		}
	}
	// the SDK identity manager does not persist the certificates
	// we have to retrieve it from the identity manager
	si, err := w.identityMgr.GetSigningIdentity(username)
	if err != nil && err != msp.ErrUserNotFound {
		return nil, restutil.NewRestError(err.Error(), 500)
	}
	if err == nil {
		// the user may have been enrolled by a different client instance
		ecert := si.EnrollmentCertificate()
		mspId := si.Identifier().MSPID
		newId.MSPID = mspId
		newId.EnrollmentCert = ecert
	}
	newId.Organization = w.identityConfig.Client().Organization

	// the SDK doesn't save the CACert locally, we have to retrieve it from the Fabric CA server
	cacert, err := w.getCACert()
	if err != nil {
		return nil, restutil.NewRestError(err.Error(), 500)
	}

	newId.CACert = cacert
	return &newId, nil
}

func (w *idClientWrapper) getCACert() ([]byte, error) {
	result, err := w.caClient.GetCAInfo()
	if err != nil {
		log.Errorf("Failed to retrieve Fabric CA information: %s", err)
		return nil, err
	}
	return result.CAChain, nil
}

func (w *idClientWrapper) AddSignerUpdateListener(listener SignerUpdateListener) {
	w.listeners = append(w.listeners, listener)
}

func (w *idClientWrapper) notifySignerUpdate(signer string) {
	for _, listener := range w.listeners {
		listener.SignerUpdated(signer)
	}
}
