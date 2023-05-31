package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"

	handlers "github.com/hyperledger/firefly-fabconnect/internal/fabric/ext-wallet/api"
	walletApi "github.com/hyperledger/firefly-fabconnect/internal/fabric/ext-wallet/api"
)

// VaultIdentity represents identity using Vault Transit
type Identity struct {
	MSPID   string `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	IDBytes []byte `protobuf:"bytes,2,opt,name=idBytes,proto3" json:"idBytes,omitempty"`
	Key     *Key   `json:"-"`

	Handler *walletApi.WalletApiHandler `json:"-"`
}

// Reset resets struct
func (m *Identity) Reset() {
	m = &Identity{}
}

// String converts struct to string reprezentation
func (m *Identity) String() string {
	return proto.CompactTextString(m)
}

// ProtoMessage indicates the identity is Protobuf serializable
func (m *Identity) ProtoMessage() {}

// Identifier returns the identifier of that identity
func (m *Identity) Identifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		ID:    m.Key.id,
		MSPID: m.MSPID,
	}
}

// Verify a signature over some message using this identity as reference
func (m *Identity) Verify(msg []byte, sig []byte) error {
	m.Handler.Verify(m.Key.SKI(), msg, sig)

	// verified, err := h.Verify(m.Key.SKI(), msg, sig)
	verified, err := m.Handler.Verify(m.Key.SKI(), msg, sig)
	if err != nil {
		return err
	}
	if !verified {
		return errors.New("signature verification failed")
	}
	return nil
}

// Serialize converts an identity to bytes
func (m *Identity) Serialize() ([]byte, error) {
	ident, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ident, nil
}

// EnrollmentCertificate Returns the underlying ECert representing this user’s identity.
func (m *Identity) EnrollmentCertificate() []byte {
	return m.IDBytes
}

// SigningIdentity represents singing identity using Vault Transit
type SigningIdentity struct {
	*Identity
}

// NewSigningIdentity initializes SigningIdentity
func NewSigningIdentity(mspid, user, remoteHost string) (*SigningIdentity, error) {
	h := handlers.NewWalletApiHandler(remoteHost, mspid)

	cert, err := h.GetIdentity(user)
	if err != nil {
		return nil, err
	}

	fmt.Printf("NewSigningIdentity: cert: %s, %s\n", user, cert)
	
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
			MSPID:   mspid,
			Key:     &Key{id: user, pubkey: ecdsaPubKey},
			IDBytes: []byte(cert),
			Handler: handlers.NewWalletApiHandler(remoteHost, mspid),
		},
	}

	return identity, nil
}

// Sign the message
func (s *SigningIdentity) Sign(msg []byte) ([]byte, error) {
	sig, err := s.Handler.Sign(s.Key.SKI(), msg)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// PublicVersion returns the public parts of this identity
func (s *SigningIdentity) PublicVersion() msp.Identity {
	return s
}

// PrivateKey returns the crypto suite representation of the private key
func (s *SigningIdentity) PrivateKey() core.Key {
	return s.Key
}

// Key core.Key wrapper for *ecdsa.PublicKey
type Key struct {
	id     string
	pubkey *ecdsa.PublicKey
}

func NewKey(id string, pubKey *ecdsa.PublicKey) *Key {
	return &Key{id: id, pubkey: pubKey}
}

// Bytes converts this key to its byte representation.
func (k Key) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k Key) SKI() (ski []byte) {
	if k.pubkey == nil {
		return nil
	}

	ecdsaPubKeyBytes := elliptic.Marshal(k.pubkey.Curve, k.pubkey.X, k.pubkey.Y)
	hash := sha256.New()
	hash.Write(ecdsaPubKeyBytes)
	ski = hash.Sum(nil)

	return ski
}

// Symmetric returns true if this key is a symmetric key, false otherwise.
func (k Key) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key, false otherwise.
func (k Key) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
func (k Key) PublicKey() (core.Key, error) {
	return k, nil
}
