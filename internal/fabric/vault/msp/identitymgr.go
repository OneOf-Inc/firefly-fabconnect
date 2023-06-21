package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	fabcore "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config/cryptoutil"

	"github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/core"
	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"

	"github.com/pkg/errors"
)

type IdentityManager struct {
	orgName         string
	orgMSPID        string
	config          fab.EndpointConfig
	cryptoSuite     fabcore.CryptoSuite
	embeddedUsers   map[string]fab.CertKeyPair
	mspPrivKeyStore fabcore.KVStore
	mspCertStore    fabcore.KVStore
	mspSecretStore  fabcore.KVStore
	userStore       msp.UserStore
}

func NewIdentityManager(orgName string, userStore msp.UserStore, cryptoSuite fabcore.CryptoSuite, endpointConfig fab.EndpointConfig, vault *vault.Vault, db kvstore.KVStore) (*IdentityManager, error) {
	netConfig := endpointConfig.NetworkConfig()
	// viper keys are case insensitive
	orgConfig, ok := netConfig.Organizations[strings.ToLower(orgName)]
	if !ok {
		return nil, fmt.Errorf("org config retrieval failed")
	}

	if orgConfig.CryptoPath == "" && len(orgConfig.Users) == 0 {
		return nil, fmt.Errorf("Either a cryptopath or an embedded list of users is required")
	}

	mspPrivKeyStore, err := NewVaultKeyStore(orgConfig.MSPID, vault, db)
	if err != nil {
		return nil, fmt.Errorf("creating a key store failed: %v", err)
	}

	mspCertStore, err := NewVaultCertStore(orgConfig.MSPID, vault)
	if err != nil {
		return nil, fmt.Errorf("creating a cert store failed: %v", err)
	}

	mspSecretStore, err := NewVaultSecretsStore(orgConfig.MSPID, vault)
	if err != nil {
		return nil, fmt.Errorf("creating a cert store failed: %v", err)
	}

	mgr := &IdentityManager{
		orgName:         orgName,
		orgMSPID:        orgConfig.MSPID,
		config:          endpointConfig,
		cryptoSuite:     cryptoSuite,
		mspPrivKeyStore: mspPrivKeyStore,
		mspCertStore:    mspCertStore,
		mspSecretStore:  mspSecretStore,
		embeddedUsers:   orgConfig.Users,
		userStore:       userStore,
	}
	return mgr, nil
}

func (mgr *IdentityManager) CreateSigningIdentity(opts ...msp.SigningIdentityOption) (msp.SigningIdentity, error) {
	opt := msp.IdentityOption{}
	for _, param := range opts {
		err := param(&opt)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create identity")
		}
	}
	if opt.Cert == nil {
		return nil, errors.New("missing certificate")
	}
	var privateKey fabcore.Key
	if opt.PrivateKey == nil {
		pubKey, err := cryptoutil.GetPublicKeyFromCert(opt.Cert, mgr.cryptoSuite)
		if err != nil {
			return nil, errors.WithMessage(err, "fetching public key from cert failed")
		}
		privateKey, err = mgr.cryptoSuite.GetKey(pubKey.SKI())
		if err != nil {
			return nil, errors.WithMessage(err, "could not find matching key for SKI")
		}
	} else {
		var err error
		privateKey, err = mgr.cryptoSuite.KeyImport(opt.PrivateKey, nil)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to import key")
		}
	}

	return NewUser("", mgr.orgMSPID, opt.Cert, privateKey), nil
}

func (mgr *IdentityManager) GetSigningIdentity(id string) (msp.SigningIdentity, error) {
	user, err := mgr.GetUser(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (mgr *IdentityManager) GetUser(username string) (*User, error) {
	cert, err := mgr.mspCertStore.Load(username)

	// if err contains "secret not found"
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			return nil, msp.ErrUserNotFound
		}
		return nil, err
	}
	certString := string(cert.(string))
	certBytes := []byte(certString)

	// exteract SKI from certificate
	ski, err := skiFromCert([]byte(certString))
	if err != nil {
		return nil, fmt.Errorf("failed to extract SKI from certificate: %v", err)
	}

	priv, err := mgr.mspPrivKeyStore.Load(ski)
	if err != nil {
		return nil, err
	}
	keypem, ok := priv.(string)
	if !ok {
		return nil, fmt.Errorf("private key is not of proper type")
	}
	block, _ := pem.Decode([]byte(keypem))
	if block == nil {
		return nil, errors.New("cannot decode key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid key type, expecting ECDSA Public Key")
	}

	key := core.Key{
		ID:     username,
		PubKey: ecdsaPubKey,
	}

	return NewUser(username, mgr.orgMSPID, certBytes, key), nil
}

func (*IdentityManager) NewUser(userData *msp.UserData) (*User, error) {
	return nil, nil
}

func (mgr *IdentityManager) StoreSecret(username string, secret []byte) error {
	return mgr.mspSecretStore.Store(username, secret)
}

func (mgr *IdentityManager) GetSecret(username string) ([]byte, error) {
	secret, err := mgr.mspSecretStore.Load(username)
	if err != nil {
		return nil, err
	}
	return []byte(secret.(string)), nil
}

func skiFromCert(certBytes []byte) (string, error) {
	block, _ := pem.Decode([]byte(string(certBytes)))
	if block == nil {
		return "", errors.New("cannot decode cert")
	}
	pubCrt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	ecdsaPubKey, ok := pubCrt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("invalid key type, expecting ECDSA Public Key")
	}
	raw := elliptic.Marshal(ecdsaPubKey.Curve, ecdsaPubKey.X, ecdsaPubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	ski := hash.Sum(nil)

	return hex.EncodeToString(ski), nil
}
