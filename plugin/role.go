package solace

import (
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"time"
)

type Role struct {
	Name                                 string
	Vpn                                  string
	Ttl                                  time.Duration
	ConfigName                           string
	ACLProfile                           string
	ClientProfile                        string
	GuaranteedEndpointPermissionOverride bool
	SubscriptionManager                  bool
	UsernamePrefix                       string
}

func (r *Role) String() string {
	return fmt.Sprintf("name=%s, vpn=%s, ttl=%s, acl=%s, client_profile=%s, config_name=%s, guaranteed_endpoint_permission_override=%t, subscription_manager=%t, username_prefix=%s", r.Name, r.Vpn, r.Ttl.String(), r.ACLProfile, r.ClientProfile, r.ConfigName, r.GuaranteedEndpointPermissionOverride, r.SubscriptionManager, r.UsernamePrefix)
}

func data2role(data *framework.FieldData) (*Role, error) {
	role := &Role{}

	nameRaw, ok := data.GetOk("name")
	if !ok {
		return nil, errors.New("Role name is mandatory")
	}
	role.Name = nameRaw.(string)
	if len(role.Name) == 0 {
		return nil, errors.New("Role name is mandatory")
	}

	vpnRaw, ok := data.GetOk("vpn")
	if ok {
		role.Vpn = vpnRaw.(string)
	}

	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		role.Ttl = time.Duration(ttlRaw.(int))
	}

	aclRaw, ok := data.GetOk("acl_profile")
	if ok {
		role.ACLProfile = aclRaw.(string)
	}

	clientProfileRaw, ok := data.GetOk("client_profile")
	if ok {
		role.ClientProfile = clientProfileRaw.(string)
	}

	configRaw, ok := data.GetOk("config_name")
	if ok {
		role.ConfigName = configRaw.(string)
	}

	gepoRaw, ok := data.GetOk("guaranteed_endpoint_permission_override")
	if ok {
		role.GuaranteedEndpointPermissionOverride = gepoRaw.(bool)
	}

	smRaw, ok := data.GetOk("subscription_manager")
	if ok {
		role.SubscriptionManager = smRaw.(bool)
	}

	prefixRaw, ok := data.GetOk("username_prefix")
	if ok {
		role.UsernamePrefix = prefixRaw.(string)
	}

	return role, nil
}
