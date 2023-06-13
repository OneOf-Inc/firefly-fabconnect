package vault

import "testing"

func init_secret_tests() (*Secret, error) {
	var cfg = &Config{
		Address:  "http://localhost:8200",
		RoleID:   "8c89a98e-db84-be76-a00c-c9b31fc9791a",
		SecretID: "e6a38fb2-ab73-c5ef-04c3-daef6db5b679",
	}

	c, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	s := c.SecretWithMountPoint("secret")

	return s, nil
}

func TestVaultSecret(t *testing.T) {
	s, err := init_secret_tests()
	if err != nil {
		t.Fatal(err)
	}

	path := "test"
	data := map[string]interface{}{
		"foo": "bar",
	}

	err = s.WriteSecret(path, data)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := s.ReadSecret(path)
	if err != nil {
		t.Fatal(err)
	}

	if secret["foo"] != "bar" {
		t.Fatal("secret does not match")
	}
}