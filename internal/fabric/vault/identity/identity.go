package identity

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type Identity struct {
	MSPID   string    `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	IDBytes []byte    `protobuf:"bytes,2,opt,name=idBytes,proto3" json:"idBytes,omitempty"`
	Key     *Key `json:"-"`

	VaultTransit *vault.Transit
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
		ID:    m.Key.ID,
		MSPID: m.MSPID,
	}
}

// Verify a signature over some message using this identity as reference
func (m *Identity) Verify(msg []byte, sig []byte) error {
	v, err := m.VaultTransit.Verify(m.Key.ID, msg, sig, &vault.SignOpts{Hash: "sha2-256", Preshashed: false})
	if err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	}
	if !v {
		return fmt.Errorf("signature verification failed")
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
