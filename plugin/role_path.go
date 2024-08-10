package solace

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
	"time"
)

const roleStoragePrefix = "roles"

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Name of the role`,
			},
			"config_name": {
				Type:        framework.TypeString,
				Description: `Configuration/backend name associated with the role`,
			},
			"vpn": {
				Type:        framework.TypeString,
				Description: `Name of the VPN`,
			},
			"ttl": {
				Type:        framework.TypeSignedDurationSecond,
				Description: `TTL for the users/creds to be created`,
			},
			"acl_profile": {
				Type:        framework.TypeString,
				Description: `Solace ACL profile name`,
			},
			"client_profile": {
				Type:        framework.TypeString,
				Description: `Solace client profile name`,
			},
			"guaranteed_endpoint_permission_override": {
				Type:        framework.TypeBool,
				Description: `Guaranteed Endpoint Permission Override`,
			},
			"subscription_manager": {
				Type:        framework.TypeBool,
				Description: `Enables subscription manager for client username`,
			},
			"username_prefix": {
				Type:        framework.TypeString,
				Description: `Non-random portion of the username`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.readRole,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.createRole,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.updateRole,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.deleteRole,
			},
		},
		ExistenceCheck:  b.roleExCheck,
		HelpSynopsis:    `Role is used to generate dynamic credentials.`,
		HelpDescription: `Role is used to generate dynamic credentials.`,
	}
}

func (b *backend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "roles/",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.listRoles,
			},
		},
	}
}

func (b *backend) listRoles(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	b.bLock.RLock()
	defer b.bLock.RUnlock()
	roles, err := req.Storage.List(ctx, roleStoragePrefix+"/")
	if err != nil {
		logger.Error("listRoles", err)
		return nil, err
	}
	logger.Debug("listRoles", "roles", roles)
	return logical.ListResponse(roles), nil
}

func (b *backend) fetchRole(ctx context.Context, req *logical.Request, name string) (*Role, error) {
	var dummy Role

	b.bLock.RLock()
	se, err := req.Storage.Get(ctx, fmt.Sprintf("%s/%s", roleStoragePrefix, name))
	b.bLock.RUnlock()

	if err != nil {
		return nil, err
	}
	if se == nil {
		return nil, nil
	}
	err = se.DecodeJSON(&dummy)
	// FIXME! first version of Role had TTL as string. Trying to overcome marshalling issues here.
	if err != nil {
		type Role1 struct {
			Name          string
			Vpn           string
			TTL           string
			ConfigName    string
			ACLProfile    string
			ClientProfile string
		}
		var dr Role1
		err = se.DecodeJSON(&dr)
		if err != nil {
			return nil, err
		}
		ttl, err := time.ParseDuration(dr.TTL + "s")
		if err != nil {
			return nil, err
		}
		return &Role{
			Name:          dr.Name,
			Vpn:           dr.Vpn,
			TTL:           ttl,
			ConfigName:    dr.ConfigName,
			ACLProfile:    dr.ACLProfile,
			ClientProfile: dr.ClientProfile,
		}, nil

	}
	return &dummy, err
}

func (b *backend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("readRole:", "req.Path", req.Path)

	roleRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("role name is required"), nil
	}
	role := roleRaw.(string)
	dummy, err := b.fetchRole(ctx, req, role)
	if err != nil {
		logger.Error("readRole:", "error ", err)
		return nil, err
	}
	if dummy == nil {
		logger.Debug("readRole", "role not found", role)
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"name":           dummy.Name,
			"vpn":            dummy.Vpn,
			"ttl":            dummy.TTL,
			"acl_profile":    dummy.ACLProfile,
			"client_profile": dummy.ClientProfile,
			"config_name":    dummy.ConfigName,
			"guaranteed_endpoint_permission_override": dummy.GuaranteedEndpointPermissionOverride,
			"subscription_manager":                    dummy.SubscriptionManager,
			"username_prefix":                         dummy.UsernamePrefix,
		},
	}, nil

}

func (b *backend) createRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("createRole:", "path", req.Path, "req.Data", req.Data)

	role, err := data2role(data)
	if err != nil {
		logger.Error("createRole", "error from data2role", err)
		return logical.ErrorResponse("createRole", "error", err), nil
	}
	logger.Debug("createRole", "role from data", role)

	if len(role.Vpn) == 0 {
		return logical.ErrorResponse("createRole", "vpn is required"), nil
	}
	if role.TTL == 0 {
		return logical.ErrorResponse("ttl is required"), nil
	}
	if len(role.ConfigName) == 0 {
		return logical.ErrorResponse("config_name is required"), nil
	}

	// If we didn't receive guaranteed_endpoint_permission_override, switch default to true
	_, ok := data.GetOk("guaranteed_endpoint_permission_override")
	if !ok {
		role.GuaranteedEndpointPermissionOverride = true
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", roleStoragePrefix, role.Name), role)
	if err != nil {
		return logical.ErrorResponse("readRole", "error", err), nil
	}

	b.bLock.Lock()
	defer b.bLock.Unlock()
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return logical.ErrorResponse("readRole", "error", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":           role.Name,
			"Vpn":            role.Vpn,
			"ttl":            time.Duration(role.TTL * time.Second).String(),
			"acl_profile":    role.ACLProfile,
			"client_profile": role.ClientProfile,
			"config_name":    role.ConfigName,
			"guaranteed_endpoint_permission_override": role.GuaranteedEndpointPermissionOverride,
			"subscription_manager":                    role.SubscriptionManager,
			"username_prefix":                         role.UsernamePrefix,
		},
	}, nil

}

// FIXME: needs locking
func (b *backend) updateRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("updateRole:", "path", req.Path, "req.Data", req.Data)
	resp, err := b.readRole(ctx, req, data)
	if err != nil {
		logger.Error("updateRole", err)
		return logical.ErrorResponse("updateRole", "error", err), nil
	}
	if resp == nil {
		return b.createRole(ctx, req, data)
	}
	if resp.IsError() {
		logger.Error("updateRole", "error", resp.Error())
		return logical.ErrorResponse("updateRole", "error", resp.Data), nil
	}

	role, err := data2role(&framework.FieldData{Raw: resp.Data, Schema: b.pathRole().Fields})
	if err != nil {
		logger.Error("updateRole", "error from data2role", err)
		return logical.ErrorResponse("updateRole", "error", err), nil
	}
	logger.Debug("updateRole", "role from storage", role)

	roleToUpdate, err := data2role(data)
	if err != nil {
		return logical.ErrorResponse("updateRole", "error", "Missing role name in request"), nil
	}
	logger.Debug("updateRole", "role to update", roleToUpdate)

	if role.Vpn != roleToUpdate.Vpn && len(roleToUpdate.Vpn) > 0 {
		role.Vpn = roleToUpdate.Vpn
	}

	if role.TTL != roleToUpdate.TTL {
		role.TTL = roleToUpdate.TTL
	}

	if role.ConfigName != roleToUpdate.ConfigName && len(roleToUpdate.ConfigName) > 0 {
		role.ConfigName = roleToUpdate.ConfigName
	}

	if role.ACLProfile != roleToUpdate.ACLProfile && len(roleToUpdate.ACLProfile) > 0 {
		role.ACLProfile = roleToUpdate.ACLProfile
	}

	if role.ClientProfile != roleToUpdate.ClientProfile && len(roleToUpdate.ClientProfile) > 0 {
		role.ClientProfile = roleToUpdate.ClientProfile
	}

	if role.UsernamePrefix != roleToUpdate.UsernamePrefix && len(roleToUpdate.UsernamePrefix) > 0 {
		role.UsernamePrefix = roleToUpdate.UsernamePrefix
	}

	// No way to tell if 'false' came from the data or is just uncheck, so override data2role() here.
	gepoRaw, ok := data.GetOk("guaranteed_endpoint_permission_override")
	if ok {
		role.GuaranteedEndpointPermissionOverride = gepoRaw.(bool)
	}

	smRaw, ok := data.GetOk("subscription_manager")
	if ok {
		role.SubscriptionManager = smRaw.(bool)
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", roleStoragePrefix, role.Name), role)
	if err != nil {
		logger.Error("updateRole", "error from storage", err)
		return logical.ErrorResponse("updateRole", "error", err), nil
	}

	b.bLock.Lock()
	defer b.bLock.Unlock()
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		logger.Error("updateRole", "Srorage.Put", err)
		return logical.ErrorResponse("updateRole", "error", err), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":           role.Name,
			"Vpn":            role.Vpn,
			"ttl":            time.Duration(role.TTL * time.Second).String(),
			"acl_profile":    role.ACLProfile,
			"client_profile": role.ClientProfile,
			"config_name":    role.ConfigName,
			"guaranteed_endpoint_permission_override": role.GuaranteedEndpointPermissionOverride,
			"subscription_manager":                    role.SubscriptionManager,
			"username_prefix":                         role.UsernamePrefix,
		},
	}, nil
}

func (b *backend) deleteRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("deleteRole:", "path", req.Path, "req.Data", req.Data)

	name, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("Role name is required"), nil
	}

	b.bLock.Lock()
	defer b.bLock.Unlock()
	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", roleStoragePrefix, name.(string)))
	if err != nil {
		logger.Error("deleteRole", "Storage.Delete", err)
		return logical.ErrorResponse("deleteRole", "error", err), nil
	}
	return nil, nil
}

func (b *backend) roleExCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	resp, err := b.readRole(ctx, req, data)
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, nil
	}
	if resp.IsError() {
		return false, resp.Error()
	}
	return true, nil
}
