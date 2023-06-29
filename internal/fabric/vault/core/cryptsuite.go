package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	Path  string
}

const (
	DefaultKeyType = "ecdsa-p256"
)

func NewCryptoSuite(cfg *CryptoSuiteVaultConfig) (CryptoSuite, error) {
	cs := CryptoSuite{
		vault: cfg.Vault,
		path:  cfg.Path,
		keys:  make(map[string]fabcore.Key),
	}

	return cs, nil
}

func (c CryptoSuite) KeyGen(opts fabcore.KeyGenOpts) (k fabcore.Key, err error) {
	// generate ecdsa key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	pubKey := &privKey.PublicKey

	// get SKI from key
	ski, err := skiFromPubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get SKI from key: %v", err)
	}

	// import key to vault
	pb, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	if err = c.vault.Transit().ImportKey(string(ski), "ecdsa-p256", pb); err != nil {
		return nil, fmt.Errorf("failed to import key: %v", err)
	}

	key := &Key{PubKey: pubKey}

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
		ks, err := c.vault.Transit().GetKey(string(ski))
		if err != nil {
			return nil, errors.New("key not found")
		}

		block, _ := pem.Decode([]byte(ks))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		key = &Key{PubKey: pubKey.(*ecdsa.PublicKey)}
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

		sig, err := c.vault.Transit().Sign(string(ski), digest, &vault.SignOpts{Hash: "sha2-256", Preshashed: true})
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

		sig, err := c.vault.Transit().Sign(string(ski), digest, &vault.SignOpts{Hash: "sha2-256", Preshashed: true})
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

func skiFromPubKey(pubKey *ecdsa.PublicKey) (string, error) {
	raw := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	ski := hash.Sum(nil)

	return hex.EncodeToString(ski), nil
}
