package wallet

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultWallet struct {
	v     *vault.Vault
	mspid string
}

func NewVaultWallet(mspid string, cfg *vault.Config) (*VaultWallet, error) {
	v, err := vault.New(cfg)
	if err != nil {
		return nil, err
	}

	return &VaultWallet{
		v:     v,
		mspid: mspid,
	}, nil
}

func (vw *VaultWallet) Put(label string, content []byte) error {
	x := &X509Identity{}
	if err := json.Unmarshal(content, x); err != nil {
		return err
	}

	keypath := fmt.Sprintf("%s/%s", vw.mspid, label)
	if err := vw.v.Transit().ImportKey(keypath, "ecdsa-p256", []byte(x.Credentials.Key)); err != nil {
		return fmt.Errorf("failed to import key: %w", err)
	}

	certpath := fmt.Sprintf("%s/certs/%s", vw.mspid, label)
	if err := vw.v.Secret().WriteSecret(certpath, map[string]interface{}{
		"certificate": x.Credentials.Certificate,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

func (vw *VaultWallet) Get(label string) ([]byte, error) {
	certpath := fmt.Sprintf("%s/certs/%s", vw.mspid, label)

	s, err := vw.v.Secret().ReadSecret(certpath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	cert := s["certificate"].([]byte)
	x := &X509Identity{
		Version: 1,
		MspID:   vw.mspid,
		IDType:  "X.509",
		Credentials: credentials{
			Certificate: string(cert),
		},
	}
	xb, err := json.Marshal(x)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal identity: %w", err)
	}

	return xb, nil
}

func (vw *VaultWallet) Remove(label string) error {
	return fmt.Errorf("not implemented")
}

func (vw *VaultWallet) Exists(label string) bool {
	xb, err := vw.Get(label)
	if err != nil {
		return false
	}
	if len(xb) == 0 {
		return false
	}
	return true
}

func (vw *VaultWallet) List() ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}
