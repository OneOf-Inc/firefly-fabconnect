package vault

import "testing"

func init_secret_tests() (*Vault, error) {
	var cfg = &Config{
		Address:  "http://localhost:8200",
		RoleID:   "556908a8-10b6-9d07-bfba-9f057d1a848b",
		SecretID: "a38f1f47-33e0-d49c-af28-37366fb5027d",
		SecretsConfig: &SecretsConfig{
			MountPoint: "secret",
		},
	}
	
	v, err := New(cfg)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func TestVaultSecret(t *testing.T) {
	v, err := init_secret_tests()
	if err != nil {
		t.Fatal(err)
	}

	path := "test/certs/1"
	data := map[string]interface{}{
		"foo": "-----BEGIN CERTIFICATE-----\nMIICBjCCAa2gAwIBAgIUEVQ/NVg4DWWgnvBVvr2cgWhcx5IwCgYIKoZIzj0EAwIw\ncDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMQ8wDQYDVQQH\nEwZEdXJoYW0xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh\nLm9yZzEuZXhhbXBsZS5jb20wHhcNMjMwNjE0MTQyMDAwWhcNMjQwNjEzMTU1NjAw\nWjAhMQ8wDQYDVQQLEwZjbGllbnQxDjAMBgNVBAMTBWFkbWluMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEz6z9rwKzG7MHv4XeKaN9UVJqS8AvIFpgEPyY8p9mJcKX\ntJKS23pFuO23wJstNfQqcT5OgG/66pCQmPnFgvzK5aN0MHIwDgYDVR0PAQH/BAQD\nAgeAMAwGA1UdEwEB/wQCMAAwHQYDV",
	}

	err = v.Secret().WriteSecret(path, data)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := v.Secret().ReadSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(secret)

	if secret["foo"] != "bar" {
		t.Fatal("secret does not match")
	}
}