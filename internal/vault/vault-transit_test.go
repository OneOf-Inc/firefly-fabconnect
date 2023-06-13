package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	uuid "github.com/nu7hatch/gouuid"
)

func test_init() (*Transit, error) {
	var cfg = &Config{
		Address:  "http://localhost:8200",
		RoleID:   "8c89a98e-db84-be76-a00c-c9b31fc9791a",
		SecretID: "e6a38fb2-ab73-c5ef-04c3-daef6db5b679",
	}

	c, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	tr := c.TransitWithMountPoint(&TransitConfig{MountPoint: "transit"})

	return tr, nil
}

func Test_Transit(t *testing.T) {
	tr, err := test_init()
	if err != nil {
		t.Fatal(err)
	}

	keyName, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}

	err = tr.CreateKey(keyName.String(), "ecdsa-p256")
	if err != nil {
		t.Fatal(err)
	}

	key, err := tr.GetKey(keyName.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %v\n", key)

	data := []byte("test")
	signOpts := &SignOpts{
		Preshashed: false,
		Hash:       "sha2-256",
	}

	s, err := tr.Sign(keyName.String(), data, signOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Signature: %x\n", s)

	v, err := tr.Verify(keyName.String(), data, s, signOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Verified: %v\n", v)
}

func Test_GetWrappingKey(t *testing.T) {
	tr, err := test_init()
	if err != nil {
		t.Fatal(err)
	}

	key, err := tr.GetWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Key: %v\n", key)
}

func Test_ImportKey(t *testing.T) {
	tr, err := test_init()
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

	err = tr.Import(keyName.String(), "ecdsa-p256", ecdsaPrivateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
}
