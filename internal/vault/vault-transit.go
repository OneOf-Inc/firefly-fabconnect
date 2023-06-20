package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/google/tink/go/kwp/subtle"
	"github.com/hashicorp/vault/api"
)

type TransitConfig struct {
	MountPoint string
}

type Transit struct {
	c   *api.Client
	cfg *TransitConfig
}

type SignOpts struct {
	Preshashed bool
	Hash       string
}

func DefaultTranistConfig() *TransitConfig {
	return &TransitConfig{
		MountPoint: "transit",
	}
}

func WithTransitConfigFromEnv() *TransitConfig {
	return &TransitConfig{
		MountPoint: os.Getenv("VAULT_TRANSIT_MOUNT_POINT"),
	}
}

func (v *Vault) Transit() *Transit {
	return &Transit{c: v.client, cfg: v.transitCfg}
}

func (t *Transit) CreateKey(keyName string, keyType string) error {
	_, err := t.c.Logical().Write(fmt.Sprintf("%s/keys/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"type": keyType,
	})
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) ImportKey(keyName string, keyType string, key []byte) error {
	wrappingKey, err := t.getWrappingKey()
	if err != nil {
		return fmt.Errorf("failed to get wrapping key")
	}

	ciphertext, err := wrapKey(wrappingKey, key)
	if err != nil {
		return fmt.Errorf("failed to wrap key")
	}

	_, err = t.c.Logical().Write(fmt.Sprintf("%s/keys/%s/import", t.cfg.MountPoint, keyName), map[string]interface{}{
		"ciphertext":    ciphertext,
		"type":          keyType,
		"hash_function": "SHA256",
	})

	if err != nil {
		return fmt.Errorf("failed to import key")
	}

	return nil
}

func (t *Transit) GetKey(keyName string) (string, error) {
	s, err := t.c.Logical().Read(fmt.Sprintf("%s/keys/%s", t.cfg.MountPoint, keyName))
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("no key was returned")
	}

	keys, ok := s.Data["keys"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("failed to parse keys")
	}

	k := keys["1"].(map[string]interface{})
	pk, ok := k["public_key"].(string)
	if !ok {
		return "", fmt.Errorf("failed to parse public key")
	}

	return pk, nil
}

func (t *Transit) Sign(keyName string, input []byte, opts *SignOpts) ([]byte, error) {
	s, err := t.c.Logical().Write(fmt.Sprintf("%s/sign/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"prehashed":      opts.Preshashed,
		"hash_algorithm": opts.Hash,
	})
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("no signature was returned")
	}

	splitted := strings.Split(s.Data["signature"].(string), ":")
	signature, err := base64.StdEncoding.DecodeString(splitted[len(splitted)-1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}

	return signature, nil
}

func (t *Transit) Verify(keyName string, input []byte, signature []byte, opts *SignOpts) (bool, error) {
	s, err := t.c.Logical().Write(fmt.Sprintf("%s/verify/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"signature":      fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString(signature)),
		"prehashed":      opts.Preshashed,
		"hash_algorithm": opts.Hash,
	})
	if err != nil {
		return false, err
	}
	if s == nil {
		return false, fmt.Errorf("no signature was returned")
	}
	return s.Data["valid"].(bool), nil
}

func (t *Transit) getWrappingKey() (string, error) {
	s, err := t.c.Logical().Read(fmt.Sprintf("%s/wrapping_key", t.cfg.MountPoint))
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("no wrapping key was returned")
	}
	return s.Data["public_key"].(string), nil
}

func wrapKey(wrappingKeyString string, key []byte) (string, error) {
	keyBlock, _ := pem.Decode([]byte(wrappingKeyString))
	wrappingKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse wrapping key")
	}

	ephemeralAESKey := make([]byte, 32)
	_, err = rand.Read(ephemeralAESKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral AES key")
	}

	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		return "", fmt.Errorf("failed to create KWP")

	}
	wrappedTargetKey, err := wrapKWP.Wrap(key)
	if err != nil {
		return "", fmt.Errorf("failed to wrap target key")
	}

	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		wrappingKey.(*rsa.PublicKey),
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to wrap AES key")
	}

	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(combinedCiphertext)

	return ciphertextBase64, nil
}
