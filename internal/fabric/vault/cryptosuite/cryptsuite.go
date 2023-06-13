package cryptosuite

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric/bccsp/utils"
	uuid "github.com/nu7hatch/gouuid"

	"github.com/hyperledger/firefly-fabconnect/internal/fabric/vault/identity"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type CryptoSuite struct {
	vaultTransit *vault.Transit
	vaultSecret  *vault.Secret

	keys map[string]core.Key
}

type CryptoSuiteVaultConfig struct {
	VaultConfig   *vault.Config
	SecretsConfig *vault.SecretsConfig
	TransitConfig *vault.TransitConfig
}

func NewCryptoSuite(cfg *CryptoSuiteVaultConfig) (*CryptoSuite, error) {
	vc, err := vault.NewClient(cfg.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %v", err)
	}

	cs := &CryptoSuite{
		vaultTransit: vc.TransitWithConfig(cfg.TransitConfig),
		vaultSecret:  vc.SecretWithConfig(cfg.SecretsConfig),
		keys:         make(map[string]core.Key),
	}

	return cs, nil
}

func (c *CryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %v", err)
	}
	keyName := id.String()

	err = c.vaultTransit.CreateKey(keyName, "ecdsa-p256")
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %v", err)
	}

	return
}

// KeyImport imports new key to CryptoSuite key store
func (c *CryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	switch raw.(type) {
	case *x509.Certificate:
		cert := raw.(*x509.Certificate)
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key type, it must be ECDSA Public Key")
		}

		err = c.vaultSecret.WriteSecret(fmt.Sprintf("certs/%s", cert.Subject.CommonName), map[string]interface{}{
			"cert": string(cert.Raw),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to write secret: %v", err)
		}

		pk := &identity.Key{PubKey: pubKey}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	case *ecdsa.PublicKey:
		pk := &identity.Key{PubKey: raw.(*ecdsa.PublicKey)}
		c.keys[string(string(pk.SKI()))] = pk
		return pk, nil
	default:
		return nil, errors.New("unknown key type")
	}
}

func (c *CryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, ok := c.keys[string(ski)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// Hash returns hash og some data using CryptoSuite hash
func (c *CryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
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
func (c *CryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return sha256.New(), nil
}

// Sign uses Vault to sign the digest
func (c *CryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	switch k.(type) {
	case *identity.Key:
		Key := k.(*identity.Key)
		sig, err := c.vaultTransit.Sign(Key.ID, digest, &vault.SignOpts{Hash: "sha2-256", Preshashed: false})
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
func (c *CryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	switch k.(type) {
	case *identity.Key:
		ecdsaPubKey := k.(*identity.Key)
		r, s, err := utils.UnmarshalECDSASignature(signature)
		if err != nil {
			return false, fmt.Errorf("failed unmashalling signature [%s]", err)
		}
		return ecdsa.Verify(ecdsaPubKey.PubKey, digest, r, s), nil
	default:
		return false, errors.New("invalid key type")
	}
}
