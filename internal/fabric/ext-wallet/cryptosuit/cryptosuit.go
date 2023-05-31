package cryptosuit

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"

	walletApi "github.com/hyperledger/firefly-fabconnect/internal/fabric/ext-wallet/api"
	extIdentity "github.com/hyperledger/firefly-fabconnect/internal/fabric/ext-wallet/identity"
)

type CryptoSuite struct {
	Handler *walletApi.WalletApiHandler
}

func NewCryptoSuite(addr string, mspId string) *CryptoSuite {
	return &CryptoSuite{
		Handler: walletApi.NewWalletApiHandler(addr, mspId),
	}
}

func (rcs *CryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	key, err := rcs.Handler.KeyGen()
	if err != nil {
		return nil, err
	}
	// convert the result to core.Key type
	publicKey, err := DecodePublic(key.PemPublicKey)
	if err != nil {
		return nil, err
	}

	return extIdentity.NewKey(key.KeyID, publicKey), nil
}

func (rcs *CryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	return nil, fmt.Errorf("import key is not supported")
}

func (rcs *CryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, err := rcs.Handler.GetKey(ski)
	if err != nil {
		return nil, err
	}
	fmt.Printf("key: %v\n", key)

	// convert the result to core.Key type
	publicKey, err := DecodePublic(key.PemPublicKey)
	if err != nil {
		return nil, err
	}

	return extIdentity.NewKey(key.KeyID, publicKey), nil
}

func (rcs *CryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	// POST /fabric/cryptosuit/:enrollmentID/hash
	return nil, nil
}

func (rcs *CryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return nil, nil
}

func (rcs *CryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	sig, err := rcs.Handler.Sign(k.SKI(), digest)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (rcs *CryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	v, err := rcs.Handler.Verify(k.SKI(), signature, digest)
	if err != nil {
		return false, err
	}

	return v, nil
}

func DecodePublic(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return
}
