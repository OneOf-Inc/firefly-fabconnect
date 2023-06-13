package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type SigningIdentity struct {
	*Identity

	tr *vault.Transit
}

func NewSigningIdentityManager(cfg *vault.Config, transitConfig *vault.TransitConfig) (*SigningIdentity, error) {
	v, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	vaultTransit := v.TransitWithConfig(transitConfig)

	return &SigningIdentity{
		tr: vaultTransit,
	}, nil
}

// NewSigningIdentity initializes SigningIdentity
func (s *SigningIdentity) NewSigningIdentity(mspid, user, cert string) (*SigningIdentity, error) {
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, errors.New("cannot decode cert")
	}
	pubCrt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPubKey, ok := pubCrt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid key type, expecting ECDSA Public Key")
	}
	identity := &SigningIdentity{
		Identity: &Identity{
			MSPID:        mspid,
			Key:          &Key{ID: user, PubKey: ecdsaPubKey},
			IDBytes:      []byte(cert),
		},
	}

	return identity, nil
}

// Sign the message
func (s *SigningIdentity) Sign(msg []byte) ([]byte, error) {
	sig, err := s.VaultTransit.Sign(s.Key.ID, msg, &vault.SignOpts{Hash: "sha2-256", Preshashed: false})
	if err != nil {
		return nil, err
	}

	sigLowS, err := utils.SignatureToLowS(s.Key.PubKey, sig)
	if err != nil {
		return nil, err
	}

	return sigLowS, nil
}

// PublicVersion returns the public parts of this identity
func (s *SigningIdentity) PublicVersion() msp.Identity {
	return s
}

// PrivateKey returns the crypto suite representation of the private key
func (s *SigningIdentity) PrivateKey() core.Key {
	return s.Key
}
