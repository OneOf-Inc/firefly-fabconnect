package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"

	uuid "github.com/google/uuid"
	fabcore "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric/bccsp/utils"

	"github.com/hyperledger/firefly-fabconnect/internal/kvstore"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type CryptoSuite struct {
	vault *vault.Vault
	db    kvstore.KVStore
	path  string
	keys  map[string]fabcore.Key
}

type CryptoSuiteVaultConfig struct {
	Vault *vault.Vault
	DB    kvstore.KVStore
	Path  string
}

const (
	DefaultKeyType = "ecdsa-p256"
)

func NewCryptoSuite(cfg *CryptoSuiteVaultConfig) (CryptoSuite, error) {
	cs := CryptoSuite{
		vault: cfg.Vault,
		db:    cfg.DB,
		path:  cfg.Path,
		keys:  make(map[string]fabcore.Key),
	}

	return cs, nil
}

func (c CryptoSuite) KeyGen(opts fabcore.KeyGenOpts) (k fabcore.Key, err error) {
	keyId := generateKeyId()

	err = c.vault.Transit().CreateKey(keyId, DefaultKeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %v", err)
	}

	keypem, err := c.vault.Transit().GetKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %v", err)
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

	key := &Key{PubKey: ecdsaPubKey}
	ski := hex.EncodeToString(key.SKI())

	if err = c.storeKeyId(keyId, ski); err != nil {
		return nil, err
	}

	c.keys[ski] = key

	return key, nil
}

// KeyImport imports new key to CryptoSuite key store
func (c CryptoSuite) KeyImport(raw interface{}, opts fabcore.KeyImportOpts) (k fabcore.Key, err error) {
	switch raw.(type) {
	case *x509.Certificate:
		cert := raw.(*x509.Certificate)
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key type, it must be ECDSA Public Key")
		}

		err = c.vault.Secret().WriteSecret(fmt.Sprintf("%s/%s", c.path, cert.Subject.CommonName), map[string]interface{}{
			"cert": string(cert.Raw),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write secret: %v", err)
		}

		pk := &Key{PubKey: pubKey}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	case *ecdsa.PublicKey:
		pk := &Key{PubKey: raw.(*ecdsa.PublicKey)}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	default:
		return nil, errors.New("unknown key type")
	}
}

func (c CryptoSuite) GetKey(ski []byte) (k fabcore.Key, err error) {
	key, ok := c.keys[string(ski)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// Hash returns hash og some data using CryptoSuite hash
func (c CryptoSuite) Hash(msg []byte, opts fabcore.HashOpts) (hash []byte, err error) {
	h, err := c.GetHash(opts)
	if err != nil {
		return nil, err
	}
	h.Reset()
	h.Write(msg)
	defer h.Reset()

	return h.Sum(nil), nil
}

// GetHash returns CryptoSuite hash
func (c CryptoSuite) GetHash(opts fabcore.HashOpts) (h hash.Hash, err error) {
	return sha256.New(), nil
}

// Sign uses Vault to sign the digest
func (c CryptoSuite) Sign(k fabcore.Key, digest []byte, opts fabcore.SignerOpts) (signature []byte, err error) {
	switch k.(type) {
	case Key:
		Key := k.(Key)

		skiBytes := Key.SKI()
		ski := hex.EncodeToString(skiBytes)
		kid, err := c.keyIdFromSKI(ski)
		if err != nil {
			return nil, err
		}

		sig, err := c.vault.Transit().Sign(string(kid), digest, &vault.SignOpts{Hash: "sha2-256", Preshashed: true})
		if err != nil {
			return nil, err
		}
		sigLowS, err := utils.SignatureToLowS(Key.PubKey, sig)
		if err != nil {
			return nil, err
		}
		signature = sigLowS
		return signature, err
	case *Key:
		Key := k.(*Key)

		skiBytes := Key.SKI()
		ski := hex.EncodeToString(skiBytes)
		kid, err := c.keyIdFromSKI(ski)
		if err != nil {
			return nil, err
		}

		sig, err := c.vault.Transit().Sign(string(kid), digest, &vault.SignOpts{Hash: "sha2-256", Preshashed: true})
		if err != nil {
			return nil, err
		}
		sigLowS, err := utils.SignatureToLowS(Key.PubKey, sig)
		if err != nil {
			return nil, err
		}
		signature = sigLowS
		return signature, err
	default:
		return nil, errors.New("invalid key type")
	}
}

// Verify verifies if signature is created using provided key
func (c CryptoSuite) Verify(k fabcore.Key, signature, digest []byte, opts fabcore.SignerOpts) (valid bool, err error) {
	switch k.(type) {
	case *Key:
		ecdsaPubKey := k.(*Key)
		r, s, err := utils.UnmarshalECDSASignature(signature)
		if err != nil {
			return false, fmt.Errorf("failed unmashalling signature [%s]", err)
		}
		return ecdsa.Verify(ecdsaPubKey.PubKey, digest, r, s), nil
	default:
		return false, errors.New("invalid key type")
	}
}

func generateKeyId() string {
	keyId := uuid.New()
	return keyId.String()
}

func (c CryptoSuite) storeKeyId(keyId, ski string) error {
	return c.db.Put(ski, []byte(keyId))
}

func (c CryptoSuite) keyIdFromSKI(ski string) ([]byte, error) {
	return c.db.Get(ski)
}
