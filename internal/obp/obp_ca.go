package obp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	OBP_CA_IDENTITIES_URI = "/api/v1/identities"
)

type GetRegistrarCredentialsResponse struct {
	AdminKey  string `json:"adminKey"`
	AdminCert string `json:"adminCert"`
}

func (obp *OBP) GetRegistrarCredentials() (*GetRegistrarCredentialsResponse, error) {
	token, err := obp.getAdminBasicAuthToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get admin basic auth token: %w", err)
	}

	client := &http.Client{}
	url := fmt.Sprintf("%s/console/admin/api/v2/organizations/%s/adminCredentials", obp.caUrl, obp.org_id)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var err_rsp ErrorResponse
		if err := json.Unmarshal([]byte(data), &err_rsp); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("retrieve registrar failed %s", err_rsp.ErrorDescription)
	}

	var adminCreds GetRegistrarCredentialsResponse
	if err := json.Unmarshal(data, &adminCreds); err != nil {
		return nil, err
	}

	return &adminCreds, nil
}

func (obp *OBP) GetIdentities(registrarCert []byte, Sign func([]byte) ([]byte, error)) ([]byte, error) {
	uri := OBP_CA_IDENTITIES_URI

	token, err := getEcdsaAuthToken(registrarCert, uri, Sign)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	url := fmt.Sprintf("https://%s-oneof-iad.blockchain.ocp.oraclecloud.com:7443/%s", obp.org_id, uri)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, err
	}

	return data, nil
}

func (obp *OBP) GetIdentity(username string, registrarCert []byte, Sign func([]byte) ([]byte, error)) ([]byte, error) {
	uri := fmt.Sprintf("%s/%s", OBP_CA_IDENTITIES_URI, username)

	token, err := getEcdsaAuthToken(registrarCert, uri, Sign)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	url := fmt.Sprintf("https://%s-oneof-iad.blockchain.ocp.oraclecloud.com:7443/%s", obp.org_id, uri)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, err
	}

	return data, nil
}

func getEcdsaAuthToken(cert []byte, uri string, Sign func([]byte) ([]byte, error)) (string, error) {
	method := "GET"
	body := []byte("")

	b64uri := base64.StdEncoding.EncodeToString([]byte(uri))
	b64body := base64.StdEncoding.EncodeToString(body)
	b64cert := base64.StdEncoding.EncodeToString(cert)
	payload := method + "." + b64uri + "." + b64body + "." + b64cert

	h := sha256.New()
	h.Reset()
	h.Write([]byte(payload))
	defer h.Reset()
	hash := h.Sum(nil)
	sig, err := Sign(hash[:])
	if err != nil {
		return "", err
	}
	b64sig := base64.StdEncoding.EncodeToString(sig)

	token := b64cert + "." + b64sig

	return token, nil
}

func (obp *OBP) getAdminBasicAuthToken() (string, error) {
	admin, err := obp.v.Secret().ReadSecret("OBP/admin")
	if err != nil {
		return "", fmt.Errorf("failed to read admin secret from vault: %w", err)
	}
	if admin == nil || admin["ADMIN_ID"] == nil || admin["ADMIN_PASSWORD"] == nil {
		return "", fmt.Errorf("admin secret not found in vault")
	}
	adminID := admin["ADMIN_ID"].(string)
	adminPassword := admin["ADMIN_PASSWORD"].(string)
	token := getBasicAuthToken(adminID, adminPassword)

	return token, nil
}
