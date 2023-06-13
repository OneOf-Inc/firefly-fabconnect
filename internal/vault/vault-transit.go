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
)

type TransitConfig struct {
	MountPoint string
}

type Transit struct {
	c   *Client
	cfg *TransitConfig
}

type SignOpts struct {
	Preshashed bool
	Hash       string
}

func WithTransitConfigFromEnv() (*TransitConfig) {
	return &TransitConfig{
		MountPoint: os.Getenv("VAULT_TRANSIT_MOUNT_POINT"),
	}
}

func (c *Client) TransitWithMountPoint(cfg *TransitConfig) *Transit {
	return &Transit{c, cfg}
}

func (t *Transit) CreateKey(keyName string, keyType string) error {
	_, err := t.c.client.Logical().Write(fmt.Sprintf("%s/keys/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"type": keyType,
	})
	if err != nil {
		return err
	}
	return nil
}

func (t *Transit) Import(keyName string, keyType string, key []byte) error {
	wrappingKey, err := t.GetWrappingKey()
	if err != nil {
		return fmt.Errorf("failed to get wrapping key")
	}

	ciphertext, err := wrapKey(wrappingKey, key)
	if err != nil {
		return fmt.Errorf("failed to wrap key")
	}

	_, err = t.c.client.Logical().Write(fmt.Sprintf("%s/keys/%s/import", t.cfg.MountPoint, keyName), map[string]interface{}{
		"ciphertext":    ciphertext,
		"type":          keyType,
		"hash_function": "SHA256",
	})

	if err != nil {
		return fmt.Errorf("failed to import key")
	}

	return nil
}

func (t *Transit) GetWrappingKey() (string, error) {
	s, err := t.c.client.Logical().Read(fmt.Sprintf("%s/wrapping_key", t.cfg.MountPoint))
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("no wrapping key was returned")
	}
	return s.Data["public_key"].(string), nil
}

func (t *Transit) GetKey(keyName string) (map[string]interface{}, error) {
	s, err := t.c.client.Logical().Read(fmt.Sprintf("%s/keys/%s", t.cfg.MountPoint, keyName))
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("no key was returned")
	}
	return s.Data, nil
}

func (t *Transit) Sign(keyName string, input []byte, opts *SignOpts) ([]byte, error) {
	s, err := t.c.client.Logical().Write(fmt.Sprintf("%s/sign/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
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
	fmt.Printf("input:%s\n", base64.StdEncoding.EncodeToString(input))
	fmt.Printf("vault:v1:%s\n", base64.StdEncoding.EncodeToString(signature))
	fmt.Printf("prehashed:%v\n", keyName)

	s, err := t.c.client.Logical().Write(fmt.Sprintf("%s/verify/%s", t.cfg.MountPoint, "95788e65-3fdf-4209-7b75-56f0c9ddf506"), map[string]interface{}{
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
