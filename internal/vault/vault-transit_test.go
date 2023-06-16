package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"

	uuid "github.com/nu7hatch/gouuid"
)

func test_init() (*Vault, error) {
	var cfg = &Config{
		Address:  "http://localhost:8200",
		RoleID:   "84860544-65ea-5829-5636-c1b1e2153cdc",
		SecretID: "349e03c3-20e9-d426-f452-6e2c2d7162b5",
		TransitConfig: &TransitConfig{
			MountPoint: "transit",
		},
	}

	v, err := New(cfg)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func Test_Transit(t *testing.T) {
	v, err := test_init()
	if err != nil {
		t.Fatal(err)
	}

	keyName, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}

	err = v.Transit().CreateKey(keyName.String(), "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Key: %v\n", keyName.String())

	key, err := v.Transit().GetKey(keyName.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %v\n", key)

	data := []byte("test")
	signOpts := &SignOpts{
		Preshashed: false,
		Hash:       "sha2-256",
	}

	s, err := v.Transit().Sign(keyName.String(), data, signOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Signature: %x\n", s)

	fmt.Printf("Key: %v\n", keyName.String())


	vrf, err := v.Transit().Verify(keyName.String(), data, s, signOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Verified: %v\n", vrf)
}

func Test_GetWrappingKey(t *testing.T) {
	v, err := test_init()
	if err != nil {
		t.Fatal(err)
	}

	key, err := v.Transit().getWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %v\n", key)
}

func Test_ImportKey(t *testing.T) {
	v, err := test_init()
	if err != nil {
		t.Fatal(err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPrivateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}

	keyName, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}

	err = v.Transit().ImportKey(keyName.String(), "ecdsa-p256", ecdsaPrivateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
}
