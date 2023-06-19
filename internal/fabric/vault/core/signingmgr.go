package core

import (
	"crypto/sha256"

	fabcore "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

type SigningManager struct {
	cryptoProvider CryptoSuite
	signOpts       fabcore.SignerOpts
}

func NewSigningManager(cryptoProvider fabcore.CryptoSuite, opts fabcore.SignerOpts) SigningManager {
	return SigningManager{
		cryptoProvider: cryptoProvider.(CryptoSuite),
		signOpts:       opts,
	}
}

func (sm SigningManager) Sign(digest []byte, key fabcore.Key) ([]byte, error) {
	// hash sha2 256
	hash := sha256.New()
	hash.Write(digest)
	hashed := hash.Sum(nil)

	return sm.cryptoProvider.Sign(key, hashed, sm.signOpts)
}
