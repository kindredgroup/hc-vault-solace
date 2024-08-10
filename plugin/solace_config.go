package solace

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
)

type solaceConfig struct {
	Name       string
	SolaceHost string
	SolacePath string
	SolaceUser string
	SolacePwd  string
	DisableTLS bool
}

func (c *solaceConfig) String() string {
	return fmt.Sprintf("name=%s, solace_host=%s, solace_path=%s, solace_user=%s, solace_pwd=, disable_tls=%t", c.Name, c.SolaceHost, c.SolacePath, c.SolaceUser, c.DisableTLS)
}

func (c *solaceConfig) toData(vars ...bool) map[string]interface{} {
	pwd := c.SolacePwd
	if len(vars) > 0 && vars[0] {
		pwd = "***"
	}

	return map[string]interface{}{
		"name":        c.Name,
		"solace_host": c.SolaceHost,
		"solace_path": c.SolacePath,
		"solace_user": c.SolaceUser,
		"solace_pwd":  pwd,
		"disable_tls": c.DisableTLS,
	}
}

// Merges data coming through framework.FieldData with solaceConfig
func (c *solaceConfig) fromData(data *framework.FieldData) {
	nameRaw, ok := data.GetOk("name")
	if ok {
		c.Name = nameRaw.(string)
	}

	hostRaw, ok := data.GetOk("host")
	if ok {
		c.SolaceHost = hostRaw.(string)
	}

	pathRaw, ok := data.GetOk("path")
	if ok {
		c.SolacePath = pathRaw.(string)
	}

	userRaw, ok := data.GetOk("username")
	if ok {
		c.SolaceUser = userRaw.(string)
	}

	pwdRaw, ok := data.GetOk("password")
	if ok {
		c.SolacePwd = pwdRaw.(string)
	}

	tlsRaw, ok := data.GetOk("disable_tls")
	if ok {
		c.DisableTLS = tlsRaw.(bool)
	}
}
