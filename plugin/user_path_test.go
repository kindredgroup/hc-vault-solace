package solace

import (
	"fmt"
	logical "github.com/hashicorp/vault/sdk/logical"
	"testing"
)

const testUser = "testuser"

// getUserPayload returns a fresh payload for user operations
func getUserPayload() map[string]interface{} {
	return map[string]interface{}{
		"role": testRoleName,
	}
}

func requireSuccessResponse(t *testing.T, action string, resp *logical.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	if resp.IsError() {
		t.Fatalf("%s: %v", action, resp.Error())
	}
}

// createTestUser creates username through the plugin and returns a closure that deletes it again.
func createTestUser(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, username string) func() {
	t.Helper()
	resp, err := createRole(b, cfg)
	requireSuccessResponse(t, "create role", resp, err)
	resp, err = callBackend("user/"+username, logical.CreateOperation, getUserPayload(), b, cfg)
	requireSuccessResponse(t, "create user "+username, resp, err)
	return func() {
		t.Helper()
		resp, err := callBackend("user/"+username, logical.DeleteOperation, getUserPayload(), b, cfg)
		requireSuccessResponse(t, "delete user "+username, resp, err)
	}
}

func readTestUser(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, username string) map[string]interface{} {
	t.Helper()
	resp, err := callBackend("user/"+username, logical.ReadOperation, getUserPayload(), b, cfg)
	requireSuccessResponse(t, "read user "+username, resp, err)
	if resp == nil {
		t.Fatalf("read user %s: missing response", username)
	}
	return resp.Data
}

// createdTestUserData creates testUser, schedules its deletion and returns what the plugin reads back.
func createdTestUserData(t *testing.T) map[string]interface{} {
	t.Helper()
	b, cfg := getBackend(t)
	t.Cleanup(createTestUser(t, b, cfg, testUser))
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
	deleteUser := createTestUser(t, b, cfg, testUser)
	deleteUser()

	if solaceUserExists(t, b, testUser) {
		t.Errorf("deleted user %q still exists in Solace", testUser)
	}
}

func TestReadUserNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", "nonexistent-user")
	userPayload := getUserPayload()

	// Try to read a user that doesn't exist
	resp, err := callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error when reading non-existent user")
	}
}

func TestReadUserInvalidVpn(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create a role with invalid VPN
	rolePayload := map[string]interface{}{
		"name":        "test-role-invalid-vpn-read",
		"vpn":         "nonexistent-vpn",
		"ttl":         "1s",
		"acl_profile": aclProfile(),
		"config_name": "default",
	}
	_, err = callBackend("roles/test-role-invalid-vpn-read", logical.CreateOperation, rolePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	userPayload := map[string]interface{}{
		"role": "test-role-invalid-vpn-read",
	}
	userPath := fmt.Sprintf("user/%s", "testuser-read-invalid-vpn")
	resp, err := callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error when reading user with invalid VPN")
	}
}

func TestWithRoleAndConfig(t *testing.T) {
	b, cfg := getBackend(t)
	userPayload := getUserPayload()
	userPayload["role"] = nil
	userPath := fmt.Sprintf("user/%s", testUser)
	resp, err := callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response from withRoleAndConfig if role is nil")
	}

	userPath = ("user/")
	_, err = callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err == nil {
		t.Fatal("Expected 'unsupported path' error")
	}
}

func TestWithRoleAndConfigRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	// Set up config but don't create the role
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	userPayload := map[string]interface{}{
		"role": "nonexistent-role",
	}
	userPath := fmt.Sprintf("user/%s", testUser)
	resp, err := callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response when role does not exist")
	}
	if resp.Error().Error() != "withRoleAndConfig: role 'nonexistent-role' not found" {
		t.Fatalf("Unexpected error message: %s", resp.Error().Error())
	}
}

func TestWithRoleAndConfigMissingConfig(t *testing.T) {
	b, cfg := getBackend(t)
	// Create a role that references a non-existent config
	rolePayload := map[string]interface{}{
		"name":        "test-role-bad-config",
		"vpn":         testVpn(),
		"ttl":         "1s",
		"acl_profile": aclProfile(),
		"config_name": "nonexistent-config",
	}
	_, err := callBackend("roles/test-role-bad-config", logical.CreateOperation, rolePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	userPayload := map[string]interface{}{
		"role": "test-role-bad-config",
	}
	userPath := fmt.Sprintf("user/%s", testUser)
	resp, err := callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response when config does not exist")
	}
	if resp.Error().Error() != "withRoleAndConfig: config 'nonexistent-config' not found" {
		t.Fatalf("Unexpected error message: %s", resp.Error().Error())
	}
}

func TestCreateUserSuccess(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", "newuser")
	userPayload := getUserPayload()

	resp, err := callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Verify response contains expected fields
	if resp.Data["username"] != "newuser" {
		t.Errorf("Expected username 'newuser', got %v", resp.Data["username"])
	}
	if resp.Data["vpn"] != testVpn() {
		t.Errorf("Expected vpn '%s', got %v", testVpn(), resp.Data["vpn"])
	}
	if resp.Data["acl_profile"] != aclProfile() {
		t.Errorf("Expected acl_profile '%s', got %v", aclProfile(), resp.Data["acl_profile"])
	}
	if resp.Data["password"] == nil || resp.Data["password"] == "" {
		t.Error("Expected password to be set")
	}

	// Cleanup
	_, err = callBackend(userPath, logical.DeleteOperation, userPayload, b, cfg)
	if err != nil {
		t.Error(err)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", "duplicateuser")
	userPayload := getUserPayload()

	// Create user first time - should succeed
	resp, err := callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Create same user again - should fail
	resp, err = callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error when creating duplicate user")
	}

	// Cleanup
	_, _ = callBackend(userPath, logical.DeleteOperation, userPayload, b, cfg)
}

func TestCreateUserInvalidVpn(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create a role with invalid VPN
	rolePayload := map[string]interface{}{
		"name":        "test-role-invalid-vpn",
		"vpn":         "nonexistent-vpn",
		"ttl":         "1s",
		"acl_profile": aclProfile(),
		"config_name": "default",
	}
	_, err = callBackend("roles/test-role-invalid-vpn", logical.CreateOperation, rolePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	userPayload := map[string]interface{}{
		"role": "test-role-invalid-vpn",
	}
	userPath := fmt.Sprintf("user/%s", "testuser-invalid-vpn")
	resp, err := callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error when creating user with invalid VPN")
	}
}
