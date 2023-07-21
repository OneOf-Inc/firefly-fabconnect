package obp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const (
	CREATE_USER_SCHEMA_URN     = "urn:ietf:params:scim:schemas:core:2.0:User"
	CHANGE_PASSWORD_SCHEMA_URN = "urn:ietf:params:scim:schemas:oracle:idcs:UserPasswordChanger"
	AUTHENTICATOR_SCHEMA_URN   = "urn:ietf:params:scim:schemas:oracle:idcs:HTTPAuthenticator"
	BULK_OPERATION_SCHEMA_URN  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	PATCH_OPERATION_SCHEMA_URN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

	CA_USER_GROUP_ID = "966988aa9f314f218287e39cd9ddc5a7"
)

type OBPConfig struct {
	IDCS_ID      string
	OrgId        string
	ClientId     string
	ClientSecret string
	Registrar    string
	Admin        string
	AdminSecret  string
}

type OBP struct {
	idcs_id string

	org_id        string
	client_id     string
	client_secret string

	Registrar   string
	Admin       string
	AdminSecret string
}

func OBPConfigFromEnv() *OBPConfig {
	return &OBPConfig{
		IDCS_ID:      os.Getenv("IDCS_ID"),
		OrgId:        os.Getenv("ORG_ID"),
		ClientId:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Registrar:    os.Getenv("REGISTRAR_ID"),
		Admin:        os.Getenv("ADMIN_ID"),
		AdminSecret:  os.Getenv("ADMIN_PASSWORD"),
	}
}

type LoginOAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type OBPUserName struct {
	FamilyName string `json:"familyName"`
	GivenName  string `json:"givenName"`
	MiddleName string `json:"middleName"`
}

type OBPGroup struct {
	Value string `json:"value"`
}

type OBPAttributes struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

type UserData struct {
	Username   string `json:"username"`
	FamilyName string `json:"familyName"`
	GivenName  string `json:"givenName"`
	MiddleName string `json:"middleName"`
	Email      string `json:"email"`
}

type CreateUserRequest struct {
	Schemas  []string        `json:"schemas"`
	UserName string          `json:"userName"`
	Name     OBPUserName     `json:"name"`
	Groups   []OBPGroup      `json:"groups"`
	Active   bool            `json:"active"`
	Password string          `json:"password"`
	Emails   []OBPAttributes `json:"emails"`
}

type CreateUserResponse struct {
	ID string `json:"id"`
}

type ChangePasswordRequest struct {
	Password string   `json:"password"`
	Schemas  []string `json:"schemas"`
}

type ChangePasswordResponse struct {
	ID string `json:"id"`
}

type ValidateUserRequest struct {
	CredType string   `json:"credType"`
	Creds    string   `json:"creds"`
	Schemas  []string `json:"schemas"`
}

type ValidateUserResponse struct {
	UserId            string `json:"userId"`
	UserDisplayName   string `json:"userDisplayName"`
	UserLoginId       string `json:"userLoginId"`
	MappingAttr       string `json:"mappingAttr"`
	SessionExpiry     string `json:"sessionExpiry"`
	Csr               bool   `json:"csr"`
	PreferredLanguage string `json:"preferredLanguage"`
	Locale            string `json:"locale"`
	Timezone          string `json:"timezone"`
	TenantName        string `json:"tenantName"`
	Type              string `json:"type"`
}

type AddUserToGroupDataOperationsValue struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type AddUserToGroupDataOperations struct {
	Op    string                              `json:"op"`
	Path  string                              `json:"path"`
	Value []AddUserToGroupDataOperationsValue `json:"value"`
}

type AddUserToGroupData struct {
	Schemas    []string                       `json:"schemas"`
	Operations []AddUserToGroupDataOperations `json:"Operations"`
}

type AddUserToGroupOperations struct {
	Method string             `json:"method"`
	Path   string             `json:"path"`
	Data   AddUserToGroupData `json:"data"`
}

type AddUserToGroupRequest struct {
	Schemas    []string                   `json:"schemas"`
	Operations []AddUserToGroupOperations `json:"Operations"`
}

type AddUserToGroupResponse struct {
	ID string `json:"id"`
}

func New(cfg *OBPConfig) *OBP {
	return &OBP{
		idcs_id:       cfg.IDCS_ID,
		org_id:        cfg.OrgId,
		client_id:     cfg.ClientId,
		client_secret: cfg.ClientSecret,
		Registrar:     cfg.Registrar,
		Admin:         cfg.Admin,
		AdminSecret:   cfg.AdminSecret,
	}
}

func (obp *OBP) getBasicAuthToken() string {
	user := fmt.Sprintf("%s-%s", obp.org_id, obp.client_id)
	token := getBasicAuthToken(user, obp.client_secret)
	return token
}

func (obp *OBP) getBaseUrl() string {
	return fmt.Sprintf("https://idcs-%s.identity.oraclecloud.com", obp.idcs_id)
}

func (obp *OBP) loginByOauth() (*LoginOAuthResponse, error) {
	url := fmt.Sprintf("%s/oauth2/v1/token", obp.getBaseUrl())
	method := "POST"

	payload := strings.NewReader("grant_type=client_credentials&scope=urn:opc:idm:__myscopes__")

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return nil, err
	}
	basicAuthToken := obp.getBasicAuthToken()
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basicAuthToken))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return nil, fmt.Errorf("login failed: %s", string(body))
	}

	var resp LoginOAuthResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (obp *OBP) CreateUser(userData *UserData, password string) (*CreateUserResponse, error) {
	login, err := obp.loginByOauth()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/admin/v1/Users", obp.getBaseUrl())
	method := "POST"

	CreateUserRequest := CreateUserRequest{
		Schemas:  []string{CREATE_USER_SCHEMA_URN},
		UserName: userData.Username,
		Name: OBPUserName{
			FamilyName: userData.FamilyName,
			GivenName:  userData.GivenName,
			MiddleName: userData.MiddleName,
		},
		Groups: []OBPGroup{
			{
				Value: CA_USER_GROUP_ID,
			},
		},
		Active:   true,
		Password: password,
		Emails: []OBPAttributes{
			{
				Value:   userData.Email,
				Type:    "work",
				Primary: true,
			},
		},
	}

	payload, err := json.Marshal(CreateUserRequest)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, io.Reader(strings.NewReader(string(payload))))

	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", login.AccessToken))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return nil, fmt.Errorf("create user failed: %s", string(body))
	}

	var resp CreateUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (obp *OBP) ChangePassword(userID, newPassword string) (*ChangePasswordResponse, error) {
	login, err := obp.loginByOauth()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/admin/v1/UserPasswordChanger/%s", obp.getBaseUrl(), userID)
	method := "PUT"

	changePasswordRequest := &ChangePasswordRequest{
		Password: newPassword,
		Schemas:  []string{CHANGE_PASSWORD_SCHEMA_URN},
	}
	payload, err := json.Marshal(changePasswordRequest)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, io.Reader(strings.NewReader(string(payload))))

	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", login.AccessToken))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return nil, fmt.Errorf("change password failed: %s", string(body))
	}

	var resp ChangePasswordResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (obp *OBP) ValidateUser(username, password string) (*ValidateUserResponse, error) {
	login, err := obp.loginByOauth()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/admin/v1/HTTPAuthenticator", obp.getBaseUrl())
	method := "POST"

	basicAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	validateUserRequest := &ValidateUserRequest{
		CredType: "authorization",
		Creds:    fmt.Sprintf("Basic %s", basicAuth),
		Schemas:  []string{AUTHENTICATOR_SCHEMA_URN},
	}
	payload, err := json.Marshal(validateUserRequest)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, io.Reader(strings.NewReader(string(payload))))

	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", login.AccessToken))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return nil, fmt.Errorf("validate user failed: %s", string(body))
	}

	var resp ValidateUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (obp *OBP) AddUserToUserCAGroup(userID string) (*AddUserToGroupResponse, error) {
	login, err := obp.loginByOauth()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/admin/v1/Groups/%s", obp.getBaseUrl(), CA_USER_GROUP_ID)
	method := "PATCH"

	addToGroupRequest := AddUserToGroupData{
		Schemas: []string{PATCH_OPERATION_SCHEMA_URN},
		Operations: []AddUserToGroupDataOperations{
			{
				Op:   "add",
				Path: "members",
				Value: []AddUserToGroupDataOperationsValue{
					{
						Value: userID,
						Type:  "User",
					},
				},
			},
		},
	}

	payload, err := json.Marshal(addToGroupRequest)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, io.Reader(strings.NewReader(string(payload))))

	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", login.AccessToken))
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 && res.StatusCode != 200 {
		return nil, fmt.Errorf("add user to ca group failed: %s", string(body))
	}


	var resp AddUserToGroupResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

type ValidatedUser struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

func (obp *OBP) CreateValidatedUser(userData *UserData) (*ValidatedUser, error) {
	password := generatePassword(12, 1, 1, 1)

	user, err := obp.CreateUser(userData, password)
	if err != nil {
		return nil, err
	}

	newPassword := generatePassword(12, 1, 1, 1)
	userID := user.ID

	_, err = obp.ChangePassword(userID, newPassword)
	if err != nil {
		return nil, err
	}

	_, err = obp.ValidateUser(userData.Username, newPassword)
	if err != nil {
		return nil, err
	}

	_, err = obp.AddUserToUserCAGroup(userID)
	if err != nil {
		return nil, err
	}

	return &ValidatedUser{
		UserID:   userID,
		Password: newPassword,
	}, nil
}
