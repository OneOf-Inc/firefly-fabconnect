package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type RemoteKey struct {
	KeyID        string `json:"keyId"`
	PemPublicKey string `json:"pemPublicKey"`
}

type RemoteSignatureRequest struct {
	Data string `json:"data"`
}

type RemoteSignatureResponse struct {
	Signature string `json:"signature"`
}

type RemoteVerifySignatureRequest struct {
	Signature string `json:"signature"`
	Data      string `json:"data"`
}

type RemoteVerifySignatureResponse struct {
	Verified bool `json:"verified"`
}

func (w *WalletApiHandler) KeyGen() (k *RemoteKey, err error) {
	// POST /fabric-cryptosuit/:enrollmentID/key
	keygen_url := fmt.Sprintf("%s/fabric-cryptosuit/key", w.addr)

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", keygen_url, bytes.NewBuffer(body))
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
	if err != nil {
		return nil, err
	}

	key := &RemoteKey{}
	err = json.Unmarshal(result, key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (w *WalletApiHandler) GetKey(ski []byte) (k *RemoteKey, err error) {
	// POST /fabric-cryptosuit/:enrollmentID/key
	getkey_url := fmt.Sprintf("%s/fabric-cryptosuit/key/%x", w.addr, string(ski))

	body := []byte(`{}`)

	// Create a HTTP GET request
	postReq, err := http.NewRequest("GET", getkey_url, bytes.NewBuffer(body))
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
	if err != nil {
		return nil, err
	}
	fmt.Printf("result: %s\n", result)

	key := &RemoteKey{}
	err = json.Unmarshal(result, key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (w *WalletApiHandler) Sign(ski []byte, digest []byte) (signature []byte, err error) {
	// POST /fabric-cryptosuit/:enrollmentID/key
	keygen_url := fmt.Sprintf("%s/fabric-cryptosuit/key/%x/sign", w.addr, string(ski))
	fmt.Printf("keygen_url: %s\n", keygen_url)

	sigReq := &RemoteSignatureRequest{
		Data: string(digest),
	}
	body, err := json.Marshal(sigReq)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", keygen_url, bytes.NewBuffer(body))
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
	if err != nil {
		return nil, err
	}
	signatureResponse := &RemoteSignatureResponse{}
	err = json.Unmarshal(result, signatureResponse)
	if err != nil {
		return nil, err
	}

	return []byte(signatureResponse.Signature), nil
}

func (w *WalletApiHandler) Verify(ski []byte, signature, digest []byte) (verified bool, err error) {
	// POST /fabric-cryptosuit/:ski/verify
	keygen_url := fmt.Sprintf("%s/fabric-cryptosuit/key/%x/verify", w.addr, string(ski))

	verifyReq := &RemoteVerifySignatureRequest{
		Signature: string(signature),
		Data:      string(digest),
	}
	body, err := json.Marshal(verifyReq)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", keygen_url, bytes.NewBuffer(body))
	if err != nil {
		return false, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	verfyResp := &RemoteVerifySignatureResponse{}
	err = json.Unmarshal(result, verfyResp)
	if err != nil {
		return false, err
	}

	return verfyResp.Verified, nil
}
