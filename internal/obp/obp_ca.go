package obp

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	OBP_CA_IDENTITIES_URI = "/api/v1/identities"
)

func (obp *OBP) GetIdentities(registrarCert []byte, Sign func([]byte) ([]byte, error)) ([]byte, error) {
	uri := OBP_CA_IDENTITIES_URI

	token, err := getEcdsaAuthToken(registrarCert, uri, Sign)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	url := "https://bps01-oneof-iad.blockchain.ocp.oraclecloud.com:7443" + uri
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
	url := "https://bps01-oneof-iad.blockchain.ocp.oraclecloud.com:7443" + uri
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
