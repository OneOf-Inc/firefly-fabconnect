package obp

import (
	"os"
)

type OBPConfig struct {
	IDCS_ID      string
	OrgID        string
	ClientId     string
	ClientSecret string
	CAUrl        string
	Registrar    string
	Admin        string
	AdminSecret  string
}

type OBP struct {
	idcs_id string

	org_id        string
	client_id     string
	client_secret string

	caUrl       string
	Registrar   string
	Admin       string
	AdminSecret string
}

func OBPConfigFromEnv() *OBPConfig {
	return &OBPConfig{
		IDCS_ID:      os.Getenv("IDCS_ID"),
		ClientId:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Admin:        os.Getenv("ADMIN_ID"),
		AdminSecret:  os.Getenv("ADMIN_PASSWORD"),
	}
}

func New(cfg *OBPConfig) *OBP {
	return &OBP{
		idcs_id:       cfg.IDCS_ID,
		client_id:     cfg.ClientId,
		client_secret: cfg.ClientSecret,
		org_id:        cfg.OrgID,
		caUrl:         cfg.CAUrl,
		Registrar:     cfg.Registrar,
		Admin:         cfg.Admin,
		AdminSecret:   cfg.AdminSecret,
	}
}
