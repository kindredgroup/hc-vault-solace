package solace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretType = "password"
)

var MaxTTL = time.Duration(11000000000000000)

func conf_data(configName string) *framework.FieldData {
	return &framework.FieldData{
		Raw: map[string]interface{}{
			"config_name": configName,
		},
		Schema: map[string]*framework.FieldSchema{
			"config_name": &framework.FieldSchema{
				Type: framework.TypeString,
			},
		},
	}
}

func (b *backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Role used to generate dynamic credentials (user)`,
			},
			"prefix": {
				Type:        framework.TypeString,
				Description: `When present, prefix will be added to the randomly generated username`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.rotateCreds,
			},
			logical.RevokeOperation: &framework.PathOperation{
				Callback: b.revokeCreds,
			},
		},
		HelpSynopsis:    `Creates dynamic credentials for given role.`,
		HelpDescription: `Creates dynamic credentials for given role.`,
	}
}

func (b *backend) secretCreds() *framework.Secret {
	return &framework.Secret{
		Type: SecretType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Solace username",
			},
			"role": {
				Type:        framework.TypeString,
				Description: "Role used to generate the credentials",
			},
			SecretType: {
				Type:        framework.TypeString,
				Description: "Password for username",
			},
		},
		Renew:  b.rotateCreds,
		Revoke: b.revokeCreds,
	}
}

func (b *backend) rotateCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("rotateCreds:")

	roleRaw, ok := data.GetOk("role")
	if !ok {
		return logical.ErrorResponse("Role name is mandatory"), nil
	}

	role, err := b.fetchRole(ctx, req, roleRaw.(string))
	if err != nil {
		logger.Error("rotateCreds", "error", err)
		return nil, err
	}
	if role == nil {
		logger.Error("rotateCreds", "role not found", roleRaw.(string))
		return logical.ErrorResponse("role not found", "role", roleRaw.(string)), nil
	}
	logger.Debug("rotateCreds", "role", role)

	cfg, err := b.fetchConfig(ctx, req, conf_data(role.ConfigName))
	if err != nil {
		logger.Error("rotateCreds", "error", err)
		return nil, err
	}

	username := uuid.New().String()
	prefix := ""
	if len(role.UsernamePrefix) > 0 {
		prefix = role.UsernamePrefix
	}
	// Prefix from the request overrides role.UsernamePrefix
	prefixRaw, ok := data.GetOk("prefix")
	if ok {
		prefix = prefixRaw.(string)
	}
	if len(prefix) > 0 {
		username = prefix + "-" + strings.SplitN(username, "-", 3)[2]
	}

	logger.Info("rotateCreds: creating user", "role", role, "username", username)
	pwd := uuid.New().String()

	err = createSolaceUser(cfg, role, username, pwd, b.Backend.Logger())
	if err != nil {
		logger.Error("rotateCreds", "error", err)
		return nil, err
	}

	secretD := map[string]interface{}{
		"username":       username,
		"password":       pwd,
		"vpn":            role.Vpn,
		"role":           role.Name,
		"acl_profile":    role.ACLProfile,
		"client_profile": role.ClientProfile,
		"ttl":            role.Ttl,
		//"guaranteed_endpoint_permission_override": role.GuaranteedEndpointPermissionOverride,
		"guaranteed_endpoint_permission_override": true,
		"subscription_manager":                    role.SubscriptionManager,
	}
	internalD := map[string]interface{}{
		"username": username,
		"role":     role.Name,
	}
	b.bLock.Lock()
	defer b.bLock.Unlock()
	resp := b.Secret(SecretType).Response(secretD, internalD)
	resp.Secret.MaxTTL = MaxTTL

	resp.Secret.TTL = role.Ttl * time.Second
	return resp, nil

}

func (b *backend) revokeCreds(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("revokeCreds", "path", req.Path)

	// FIXME: check if username is in the secret passed with the call.
	userRaw, ok := data.GetOk("username")
	if !ok {
		return logical.ErrorResponse("Username is mandatory"), nil
	}

	roleRaw, ok := data.GetOk("role")
	if !ok {
		return logical.ErrorResponse("Role is mandatory"), nil
	}
	role, err := b.fetchRole(ctx, req, roleRaw.(string))
	if err != nil {
		logger.Error("revokeCreds", "error", err)
		return nil, err
	}
	if role == nil {
		logger.Error("revokeCreds", "role not found", roleRaw.(string))
		return logical.ErrorResponse("role not found", "role", roleRaw.(string)), nil
	}

	cfg, err := b.fetchConfig(ctx, req, conf_data(role.ConfigName))
	if err != nil {
		logger.Error("rotateCreds", "error", err)
		return nil, err
	}

	logger.Info("rotateCreds: revoking user", "username", userRaw.(string), "role", role)
	_, err = deleteSolaceUser(role, cfg, userRaw.(string), logger)
	if err != nil {
		logger.Error("rotateCreds", "error", err)
		return nil, err
	}
	return nil, err
}
