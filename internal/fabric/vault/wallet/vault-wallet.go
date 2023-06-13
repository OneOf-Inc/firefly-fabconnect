package wallet

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type VaultWallet struct {
	v     *vault.Client
	t     *vault.Transit
	s     *vault.Secret
	mspid string
}

func NewVaultWallet(mspid string, cfg *vault.Config, transitConfig *vault.TransitConfig, secretsConfig *vault.SecretsConfig) (*VaultWallet, error) {
	v, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	vaultTransit := v.TransitWithConfig(transitConfig)
	vaultSecret := v.SecretWithConfig(secretsConfig)

	return &VaultWallet{
		v:     v,
		t:     vaultTransit,
		s:     vaultSecret,
		mspid: mspid,
	}, nil
}

func (vw *VaultWallet) Put(label string, content []byte) error {
	x := &X509Identity{}
	if err := json.Unmarshal(content, x); err != nil {
		return err
	}

	keypath := fmt.Sprintf("%s/%s", vw.mspid, label)
	if err := vw.t.Import(keypath, "ecdsa-p256", []byte(x.Credentials.Key)); err != nil {
		return fmt.Errorf("failed to import key: %w", err)
	}

	certpath := fmt.Sprintf("%s/certs/%s", vw.mspid, label)
	if err := vw.s.WriteSecret(certpath, map[string]interface{}{
		"certificate": x.Credentials.Certificate,
	}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

func (vw *VaultWallet) Get(label string) ([]byte, error) {
	certpath := fmt.Sprintf("%s/certs/%s", vw.mspid, label)

	s, err := vw.s.ReadSecret(certpath)
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
