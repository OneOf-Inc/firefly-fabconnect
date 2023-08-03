package obp

import (
	"os"

	"github.com/hyperledger/firefly-fabconnect/internal/vault"
)

type OBPConfig struct {
	IDCS_ID       string
	CaUserGroupID string
	OrgID         string
	CAUrl         string
	Registrar     string
}

type OBP struct {
	idcs_id          string
	ca_user_group_id string

	org_id    string
	caUrl     string
	Registrar string

	v *vault.Vault
}

func OBPConfigFromEnv() *OBPConfig {
	return &OBPConfig{
		IDCS_ID:       os.Getenv("IDCS_ID"),
		CaUserGroupID: os.Getenv("CA_USER_GROUP_ID"),
	}
}

func New(v *vault.Vault, cfg *OBPConfig) *OBP {
	return &OBP{
		idcs_id:          cfg.IDCS_ID,
		ca_user_group_id: cfg.CaUserGroupID,
		org_id:           cfg.OrgID,
		caUrl:            cfg.CAUrl,
		Registrar:        cfg.Registrar,
		v:                v,
	}
}
