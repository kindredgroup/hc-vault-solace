package solace

import (
	"context"
	"fmt"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/google/uuid"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
	models "kindredgroup.com/solace-plugin/gen/models"
	all "kindredgroup.com/solace-plugin/gen/solaceapi/all"
)

func (b *backend) pathUser() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("user/%s", framework.GenericNameRegex("username")),
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: `Name of Solace client username to create`,
			},
			"role": {
				Type:        framework.TypeString,
				Description: `Role contains configuration used to create static user`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.readUser,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.createUser,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.createUser,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.deleteUser,
			},
		},
		ExistenceCheck: b.userExCheck,
		HelpSynopsis:    `Endpoint to create static users.`,
		HelpDescription: `Endpoint to create static users. Configuration comes from role.`,
	}
}

// withRoleAndConfig is a decorator which initializes role and Solace config, and calls
// the supplied closure.
func (b *backend) withRoleAndConfig(ctx context.Context, req *logical.Request, data *framework.FieldData, f func(r *Role, c *solaceConfig, user string, l hclog.Logger) (*logical.Response, error)) (*logical.Response, error) {
	logger := b.Backend.Logger()
	roleRaw, ok := data.GetOk("role")
	if !ok {
		return logical.ErrorResponse("Role name is mandatory"), nil
	}

	role, err := b.fetchRole(ctx, req, roleRaw.(string))
	if err != nil {
		logger.Error("withRoleAndConfig", "error", err)
		return nil, err
	}
	if role == nil {
		logger.Error("withRoleAndConfig", "error", hclog.Fmt("role '%v' not found", roleRaw))
		return logical.ErrorResponse(fmt.Sprintf("withRoleAndConfig: role '%v' not found", roleRaw)), nil
	}
	logger.Debug("withRoleAndConfig", "role", role)

	cfg, err := b.fetchConfig(ctx, req, confData(role.ConfigName))
	if err != nil {
		logger.Error("withRoleAndConfig", "error", err)
		return nil, err
	}

	userRaw, ok := data.GetOk("username")
	if !ok {
		logical.ErrorResponse("missing username")
	}
	user := userRaw.(string)

	return f(role, cfg, user, logger)
}

func (b *backend) readUser(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	return b.withRoleAndConfig(ctx, req, data, func(role *Role, cfg *solaceConfig, username string, logger hclog.Logger) (*logical.Response, error) {
		client, err := getClient(cfg, logger)
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}

		params := all.NewGetMsgVpnClientUsernameParams()
		params.MsgVpnName = role.Vpn
		params.ClientUsername = username
		logger.Debug("readUser", "vpn", params.MsgVpnName, "username", params.ClientUsername)
		auth := httptransport.BasicAuth(cfg.SolaceUser, cfg.SolacePwd)
		result, err := client.GetMsgVpnClientUsername(params, auth)
		if err != nil {
			logger.Error("readUser", "error", err)
			return logical.ErrorResponse(err.Error()), err
		}
		logger.Debug("readUser", "result", result.Payload)
		pl := result.Payload.Data
		return &logical.Response{
			Data: map[string]interface{}{
				"acl_profile":                  pl.ACLProfileName,
				"client_profile":               pl.ClientProfileName,
				"username":                     pl.ClientUsername,
				"enabled":                      pl.Enabled,
				"vpn":                          pl.MsgVpnName,
				"subscription_manager_enabled": pl.SubscriptionManagerEnabled,
				"guaranteed_endpoint_permission_override": pl.GuaranteedEndpointPermissionOverrideEnabled,
			},
		}, nil
	})
}

func (b *backend) createUser(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.withRoleAndConfig(ctx, req, data, func(role *Role, cfg *solaceConfig, username string, logger hclog.Logger) (*logical.Response, error) {
		pwd := uuid.New().String()
		err := createSolaceUser(cfg, role, username, pwd, logger)
		if err != nil {
			logger.Error("createUser", "error from createSolaceUser", err)
			return logical.ErrorResponse(err.Error()), nil
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"acl_profile":                  role.ACLProfile,
				"client_profile":               role.ClientProfile,
				"username":                     username,
				"vpn":                          role.Vpn,
				"subscription_manager_enabled": role.SubscriptionManager,
				"guaranteed_endpoint_permission_override": role.GuaranteedEndpointPermissionOverride,
				"password": pwd,
			},
		}, nil
	})
}

func (b *backend) deleteUser(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.withRoleAndConfig(ctx, req, data, deleteSolaceUser)
}

// deleteSolaceUser is exposed to creds path as well, so no closure.
func deleteSolaceUser(role *Role, cfg *solaceConfig, username string, logger hclog.Logger) (*logical.Response, error) {

	logger.Info("deleteSolaceUser: deleting user", "vpn", role.Vpn, "username", username)
	client, err := getClient(cfg, logger)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}
	params := all.NewDeleteMsgVpnClientUsernameParams()
	params.MsgVpnName = role.Vpn
	params.ClientUsername = username
	auth := httptransport.BasicAuth(cfg.SolaceUser, cfg.SolacePwd)
	_, err = client.DeleteMsgVpnClientUsername(params, auth)
	return nil, err
}

// createSolaceUser is exposed to creds path as well, so no closure.
func createSolaceUser(cfg *solaceConfig, role *Role, username string, pwd string, logger hclog.Logger) error {
	client, err := getClient(cfg, logger)
	if err != nil {
		return err
	}
	params := all.NewCreateMsgVpnClientUsernameParams()
	params.MsgVpnName = role.Vpn

	params.Body = &models.MsgVpnClientUsername{
		ClientUsername:    username,
		Enabled:           true,
		Password:          pwd,
		ACLProfileName:    role.ACLProfile,
		ClientProfileName: role.ClientProfile,
		// FIXME: by the special request from PE...
		// GuaranteedEndpointPermissionOverrideEnabled: role.GuaranteedEndpointPermissionOverride,
		GuaranteedEndpointPermissionOverrideEnabled: true,
		SubscriptionManagerEnabled:                  role.SubscriptionManager,
	}

	auth := httptransport.BasicAuth(cfg.SolaceUser, cfg.SolacePwd)
	_, err = client.CreateMsgVpnClientUsername(params, auth)
	return err

}

// userExCheck is a dummy check, if the user exists in Solace, create operation will return error anyway
func (b *backend) userExCheck(_ context.Context, _ *logical.Request, _ *framework.FieldData) (bool, error) {
	return false, nil
}
