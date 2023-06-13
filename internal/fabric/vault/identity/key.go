package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

type Key struct {
	ID     string
	PubKey *ecdsa.PublicKey
}

// Bytes converts this key to its byte representation.
func (k *Key) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *Key) SKI() (ski []byte) {
	if k.PubKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key, false otherwise.
func (k *Key) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key, false otherwise.
func (k *Key) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
func (k *Key) PublicKey() (core.Key, error) {
	return k, nil
}
