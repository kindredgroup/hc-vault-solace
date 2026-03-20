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

func TestReadUser(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", testUser)
	userPayload := getUserPayload()
	resp, err := callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}

	resp, err = callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}

	resp, err = callBackend(userPath, logical.DeleteOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
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
