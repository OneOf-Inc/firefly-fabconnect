package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	mspApi "github.com/hyperledger/fabric-sdk-go/pkg/msp/api"
)

type GetIdentityResponse struct {
	Cert string `json:"cert"`
}

type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert"`
}

type RemoteRegisterRequest struct {
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	MaxEnrollments int         `json:"max_enrollments"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attributes"`
	CAName         string      `json:"caname"`
	Secret         string      `json:"secret"`
}

type RemoteEnrollResponse struct {
	Cetificate      string `json:"certificate"`
	RootCertificate string `json:"rootCertificate"`
}

type SignRequest struct {
	Message string `json:"message"`
}

func (w *WalletApiHandler) GetIdentity(keyId string) (cert string, err error) {
	getid_url := fmt.Sprintf("%s/fabric-cryptosuit/identities/%s/%s", w.addr, w.mspId, keyId)

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("GET", getid_url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	identityResponse := &GetIdentityResponse{}
	err = json.Unmarshal(result, identityResponse)
	if err != nil {
		return "", err
	}

	return identityResponse.Cert, nil
}

func (w *WalletApiHandler) Register(regReq *mspApi.RegistrationRequest) (string, error) {
	posturl := fmt.Sprintf("%s/fabric-cryptosuit/identities/%s/%s", w.addr, w.mspId, regReq.Name)

	rr := &RemoteRegisterRequest{
		Name:           regReq.Name,
		Type:           regReq.Type,
		MaxEnrollments: regReq.MaxEnrollments,
		Affiliation:    regReq.Affiliation,
		CAName:         regReq.CAName,
		Secret:         regReq.Secret,
	}
	if regReq.Attributes != nil {
		rr.Attributes = []Attribute{}
		for key := range regReq.Attributes {
			rr.Attributes = append(rr.Attributes, Attribute{
				Name:  regReq.Attributes[key].Name,
				Value: regReq.Attributes[key].Value,
				ECert: regReq.Attributes[key].ECert,
			})
		}
	}

	// convert rr to bytes
	body, err := json.Marshal(rr)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to encode register request payload: %s", err), 400)
	}

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to create remote register request: %s", err), 400)
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to register identity remotely: %s", err), 400)
	}
	defer resp.Body.Close()

	secret, _ := io.ReadAll(resp.Body)

	return string(secret), nil
}

func (w *WalletApiHandler) Enroll(enrollmentID string) ([]byte, error) {
	posturl := fmt.Sprintf("%s/fabric-cryptosuit/identities/%s/%s/enroll", w.addr, w.mspId, enrollmentID)

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, _ := io.ReadAll(resp.Body)

	return result, nil
}

func (w *WalletApiHandler) Revoke(revokeReq mspApi.RevocationRequest) (*mspApi.RevocationResponse, error) {
	fmt.Printf("revokeReq: %s\n", revokeReq.Name)
	posturl := fmt.Sprintf("%s/fabric-cryptosuit/identities/%s/%s/revoke", w.addr, w.mspId, revokeReq.Name)

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	fmt.Printf("result: %s\n", result)
	if err != nil {
		return nil, err
	}

	var revokeResult *mspApi.RevocationResponse = &mspApi.RevocationResponse{}
	if err = json.Unmarshal(result, revokeResult); err != nil {
		return nil, err
	}

	return revokeResult, err
}
