package obp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	idcs_id       = "1e2f0a4ae35f46c092deac97713b4ded"
	org_id        = "bps01"
	client_id     = "oyrwtguvzlbvt6qmrwte26iyspdflgca_APPID"
	client_secret = "285ab595-622b-46dd-8554-080b4b4b0308"
)

func TestGetBasicAuthToken(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	obpToken := obp.getBasicAuthToken()
	assert.Equal(t, "YnBzMDEtb3lyd3RndXZ6bGJ2dDZxbXJ3dGUyNml5c3BkZmxnY2FfQVBQSUQ6Mjg1YWI1OTUtNjIyYi00NmRkLTg1NTQtMDgwYjRiNGIwMzA4", obpToken)

}

func TestGetBaseUrl(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	baseUrl := obp.getBaseUrl()
	assert.Equal(t, "https://1e2f0a4ae35f46c092deac97713b4ded.identity.oraclecloud.com", baseUrl)
}

func TestLoginByOauth(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	l, err := obp.loginByOauth()
	assert.Nil(t, err)
	fmt.Printf("token: %s\n", l.AccessToken)
}

func TestCreateUser(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	userData := &UserData{
		Username:   "testuser",
		FamilyName: "testuser",
		GivenName:  "testuser",
		MiddleName: "testuser",
		Email:      "testuser@oneof.com",
	}
	password := "J!mm1mcgill007"

	user, err := obp.CreateUser(userData, password)
	assert.Nil(t, err)
	fmt.Printf("user: %s\n", user)
}

func TestChangePassword(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	newPassword := "B@bijo0n007!"
	userID := "0f4577345c3140df85ee5d3ab663f59f"

	user, err := obp.ChangePassword(userID, newPassword)
	assert.Nil(t, err)
	fmt.Printf("user: %s\n", user)
}

func TestValidateUser(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	username := "testuser"
	password := "B@bijo0n007!"

	user, err := obp.ValidateUser(username, password)
	assert.Nil(t, err)
	fmt.Printf("user: %v\n", user)
}

func TestAddUserToUserCAGroup(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	userID := "0f4577345c3140df85ee5d3ab663f59f"

	user, err := obp.AddUserToUserCAGroup(userID)
	assert.Nil(t, err)
	fmt.Printf("user: %s\n", user)
}

func TestAll(t *testing.T) {
	obp := New(&OBPConfig{
		IDCS_ID:      idcs_id,
		OrgId:        org_id,
		ClientId:     client_id,
		ClientSecret: client_secret,
	})

	userData := &UserData{
		Username:   "testuser4",
		FamilyName: "testuser",
		GivenName:  "testuser",
		MiddleName: "testuser",
		Email:      "testuser@oneof.com",
	}
	user, err := obp.CreateValidatedUser(userData)
	assert.Nil(t, err)
	fmt.Printf("user: %s\n", user)
}