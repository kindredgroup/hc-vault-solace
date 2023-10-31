package solace

import (
	"fmt"
	logical "github.com/hashicorp/vault/sdk/logical"
	"strings"
	"testing"
)

const (
	userPrefix = "testuser"
)

var rotateTestCredsPath = "creds/" + testRoleName

func TestRotateCreds(t *testing.T) {
	b, cfg := getBackend(t)

	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	createRole(b, cfg)
	resp, err := callBackend(rotateTestCredsPath, logical.ReadOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	t.Log(resp)
	user := resp.Data["username"].(string)
	t.Log(user)
	secret := resp.Secret

	userPath := fmt.Sprintf("user/%s", resp.Data["username"])
	resp, err = callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	acl := resp.Data["acl_profile"].(string)
	if acl != aclProfile {
		t.Fatal("Expected ACL profile" + aclProfile + ", received " + acl)
	}

	// clientProfile is unset, expecting to receive "default" back from Solace
	clientProfile := resp.Data["client_profile"].(string)
	if clientProfile != "default" {
		t.Fatal("Somehow received client profile: " + clientProfile)
	}
	gepo := resp.Data["guaranteed_endpoint_permission_override"].(bool)
	if gepo != guaranteedEndpointPermissionOverride {
		t.Fatal(fmt.Sprintf("Expected GuaranteedEndpointPermissionOverride: %t, received %t", guaranteedEndpointPermissionOverride, gepo))
	}

	if !strings.HasPrefix(user, testUserPrefix+"-") {
		t.Fatal("Expected prefix " + testUserPrefix + ", got username " + user)
	}

	// Revoke created user

	pl := map[string]interface{}{
		"username": user,
		"role":     testRoleName,
	}
	resp, err = callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = callBackend(fmt.Sprintf("user/%s/%s", testVpn, user), logical.ReadOperation, pl, b, cfg)

	// User should have been dropped, so expect error here
	if err == nil {
		if resp != nil {
			if !resp.IsError() {
				t.Log(resp)
				t.Fatal("received valid response")
			}
			t.Fatal(resp.Error())
		}
	}
	t.Log(err)
}

func TestPrefixCreds(t *testing.T) {
	b, cfg := getBackend(t)

	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	createRole(b, cfg)
	credsPayload := map[string]interface{}{
		"name":   configPath,
		"prefix": userPrefix,
	}
	resp, err := callBackend(rotateTestCredsPath, logical.ReadOperation, credsPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	t.Log(resp)
	user := resp.Data["username"].(string)

	pl := map[string]interface{}{
		"username": user,
		"role":     testRoleName,
	}
	resp, err = callBackend("creds/", logical.RevokeOperation, pl, b, cfg, resp.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(user, userPrefix+"-") {
		t.Fatal("Expected prefix " + userPrefix + ", got username " + user)
	}
}

func revokeCreds(b logical.Backend, cfg *logical.BackendConfig, user string, secret *logical.Secret) (*logical.Response, error) {
	pl := map[string]interface{}{
		"username": user,
		"role":     testRoleName,
	}
	return callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)

}
