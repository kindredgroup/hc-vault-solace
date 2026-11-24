package solace

import (
	"errors"
	"testing"

	logical "github.com/hashicorp/vault/sdk/logical"
)

const testUser = "testuser"

// getUserPayload returns a fresh payload for user operations
func getUserPayload() map[string]interface{} {
	return map[string]interface{}{
		"role": testRoleName,
	}
}

func writeTestConfig(t *testing.T, b logical.Backend, cfg *logical.BackendConfig) {
	t.Helper()
	if err := writeConfig(getValidPayload(), b, cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func createTestRole(t *testing.T, b logical.Backend, cfg *logical.BackendConfig) {
	t.Helper()
	resp, err := createRole(b, cfg)
	requireSuccessResponse(t, "create role", resp, err)
}

func createCustomRole(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, name, vpn, configName string) {
	t.Helper()
	resp, err := callBackend("roles/"+name, logical.CreateOperation, map[string]interface{}{
		"name":        name,
		"vpn":         vpn,
		"ttl":         "1s",
		"acl_profile": aclProfile(),
		"config_name": configName,
	}, b, cfg)
	requireSuccessResponse(t, "create role "+name, resp, err)
}

func callUserPath(b logical.Backend, cfg *logical.BackendConfig, op logical.Operation, username, role string) (*logical.Response, error) {
	return callBackend("user/"+username, op, map[string]interface{}{"role": role}, b, cfg)
}

// createTestUser creates username through the plugin and returns the create response data
// together with a closure that deletes the user again.
func createTestUser(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, username string) (map[string]interface{}, func()) {
	t.Helper()
	createTestRole(t, b, cfg)
	resp, err := callUserPath(b, cfg, logical.CreateOperation, username, testRoleName)
	data := requireResponseData(t, "create user "+username, resp, err)
	return data, func() {
		t.Helper()
		resp, err := callUserPath(b, cfg, logical.DeleteOperation, username, testRoleName)
		requireSuccessResponse(t, "delete user "+username, resp, err)
	}
}

func readTestUser(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, username string) map[string]interface{} {
	t.Helper()
	resp, err := callUserPath(b, cfg, logical.ReadOperation, username, testRoleName)
	return requireResponseData(t, "read user "+username, resp, err)
}

// createdTestUserData creates testUser, schedules its deletion and returns what the plugin reads back.
func createdTestUserData(t *testing.T) map[string]interface{} {
	t.Helper()
	b, cfg := getBackend(t)
	_, deleteUser := createTestUser(t, b, cfg, testUser)
	t.Cleanup(deleteUser)
	return readTestUser(t, b, cfg, testUser)
}

func TestReadUserReturnsUsername(t *testing.T) {
	if got := createdTestUserData(t)["username"]; got != testUser {
		t.Errorf("username = %v, want %q", got, testUser)
	}
}

func TestReadUserReturnsRoleVpn(t *testing.T) {
	if got, want := createdTestUserData(t)["vpn"], testVpn(); got != want {
		t.Errorf("vpn = %v, want %q", got, want)
	}
}

func TestReadUserReturnsRoleACLProfile(t *testing.T) {
	if got, want := createdTestUserData(t)["acl_profile"], aclProfile(); got != want {
		t.Errorf("acl_profile = %v, want %q", got, want)
	}
}

func TestReadUserReturnsEnabledUser(t *testing.T) {
	if got := createdTestUserData(t)["enabled"]; got != true {
		t.Errorf("enabled = %v, want true", got)
	}
}

func TestDeleteUserRemovesUser(t *testing.T) {
	b, cfg := getBackend(t)
	_, deleteUser := createTestUser(t, b, cfg, testUser)
	deleteUser()

	if solaceUserExists(t, b, testUser) {
		t.Errorf("deleted user %q still exists in Solace", testUser)
	}
}

func TestReadUserNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	createTestRole(t, b, cfg)
	resp, err := callUserPath(b, cfg, logical.ReadOperation, "nonexistent-user", testRoleName)
	requireAnyErrorResponse(t, resp, err)
}

func TestReadUserInvalidVpn(t *testing.T) {
	b, cfg := getBackend(t)
	writeTestConfig(t, b, cfg)
	createCustomRole(t, b, cfg, "test-role-invalid-vpn-read", "nonexistent-vpn", "default")
	resp, err := callUserPath(b, cfg, logical.ReadOperation, "testuser-read-invalid-vpn", "test-role-invalid-vpn-read")
	requireAnyErrorResponse(t, resp, err)
}

func TestWithRoleAndConfigRejectsNilRole(t *testing.T) {
	b, cfg := getBackend(t)
	nilRole := map[string]interface{}{"role": nil}
	resp, err := callBackend("user/"+testUser, logical.ReadOperation, nilRole, b, cfg)
	requireErrorResponse(t, resp, err, "withRoleAndConfig: role '' not found")
}

func TestUserPathWithoutUsernameIsUnsupported(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := callBackend("user/", logical.ReadOperation, b, cfg)
	if !errors.Is(err, logical.ErrUnsupportedPath) {
		t.Fatalf("error = %v, want %v", err, logical.ErrUnsupportedPath)
	}
}

func TestWithRoleAndConfigRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	writeTestConfig(t, b, cfg)
	resp, err := callUserPath(b, cfg, logical.ReadOperation, testUser, "nonexistent-role")
	requireErrorResponse(t, resp, err, "withRoleAndConfig: role 'nonexistent-role' not found")
}

func TestWithRoleAndConfigMissingConfig(t *testing.T) {
	b, cfg := getBackend(t)
	createCustomRole(t, b, cfg, "test-role-bad-config", testVpn(), "nonexistent-config")
	resp, err := callUserPath(b, cfg, logical.ReadOperation, testUser, "test-role-bad-config")
	requireErrorResponse(t, resp, err, "withRoleAndConfig: config 'nonexistent-config' not found")
}

func TestCreateUserSuccess(t *testing.T) {
	const username = "newuser"
	b, cfg := getBackend(t)
	data, deleteUser := createTestUser(t, b, cfg, username)
	t.Cleanup(deleteUser)

	if got := data["username"]; got != username {
		t.Errorf("username = %v, want %q", got, username)
	}
	if got, want := data["vpn"], testVpn(); got != want {
		t.Errorf("vpn = %v, want %q", got, want)
	}
	if got, want := data["acl_profile"], aclProfile(); got != want {
		t.Errorf("acl_profile = %v, want %q", got, want)
	}
	if got := data["password"]; got == nil || got == "" {
		t.Error("expected password to be set")
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	const username = "duplicateuser"
	b, cfg := getBackend(t)
	_, deleteUser := createTestUser(t, b, cfg, username)
	t.Cleanup(deleteUser)

	resp, err := callUserPath(b, cfg, logical.CreateOperation, username, testRoleName)
	requireAnyErrorResponse(t, resp, err)
}

func TestCreateUserInvalidVpn(t *testing.T) {
	b, cfg := getBackend(t)
	writeTestConfig(t, b, cfg)
	createCustomRole(t, b, cfg, "test-role-invalid-vpn", "nonexistent-vpn", "default")
	resp, err := callUserPath(b, cfg, logical.CreateOperation, "testuser-invalid-vpn", "test-role-invalid-vpn")
	requireAnyErrorResponse(t, resp, err)
}
