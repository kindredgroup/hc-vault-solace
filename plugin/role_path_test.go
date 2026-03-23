package solace

import (
	"context"
	logical "github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
)

const (
	testRoleName                         = "test1role"
	testRolePath                         = "roles/test1role"
	wrongRole                            = "does-not-exist"
	wrongRolePath                        = "roles/does-not-exist"
	credTTL                              = 1
	guaranteedEndpointPermissionOverride = true
	testUserPrefix                       = "slowBoring"
)

func fetchAndCheckOne(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, path string, searchStr string) bool {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      path,
		Data:      nil,
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Log(err)
		return false
	}
	if resp.IsError() {
		t.Log(resp.Error())
		return false
	}
	if (resp.Data == nil) || (resp.Data["keys"] == nil) {
		t.Log("No roles found")
		return false
	}

	var out []string = resp.Data["keys"].([]string)
	if out[0] != searchStr {
		t.Log("String " + searchStr + " not found")
		return false
	}
	return true
}

func fetchAndCheckRole(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, searchStr string) bool {
	return fetchAndCheckOne(t, b, cfg, "roles/", searchStr)
}

func createRole(b logical.Backend, cfg *logical.BackendConfig) (*logical.Response, error) {
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)
	pl := map[string]interface{}{
		"name":            testRoleName,
		"vpn":             testVpn(),
		"ttl":             credTTL,
		"acl_profile":     aclProfile(),
		"client_profile":  nil,
		"config_name":     "default",
		"username_prefix": testUserPrefix,
	}
	return callBackend(testRolePath, logical.CreateOperation, pl, b, cfg)
}

func TestListRoles(t *testing.T) {
	b, cfg := getBackend(t)
	createRole(b, cfg)
	if !fetchAndCheckRole(t, b, cfg, testRoleName) {
		t.Fatal("Created role not found")
	}
	if fetchAndCheckRole(t, b, cfg, wrongRole) {
		t.Fatal("Non-existing role found")
	}
}

func TestCreateRole(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	t.Log(resp.Data)

	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	t.Log(resp.Data)

	resp, err = callBackend(testRolePath, logical.DeleteOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if resp != nil {
		t.Fatal("Found deleted role")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadRole(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := callBackend(wrongRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("Found non-existing role")
	}
}

// Deleting non-existing key succeeds somehow
func TestDeleteRole(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := callBackend(wrongRolePath, logical.DeleteOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Log(resp.Data)
	}
	if resp.IsError() {
		t.Fatal("Deleting non-existing role failed")
	}
}

func TestUpdateRole(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pl := map[string]interface{}{
		"name":           testRoleName,
		"ttl":            "0s",
		"acl_profile":    aclProfile(),
		"client_profile": clientProfile(),
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      testRolePath,
		Data:      pl,
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Log(resp.Error())
		t.Fatal("Writing role failed")
	}
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Log(resp.Data)
		t.Fatal("Writing role failed")
	}
	t.Log(resp.Data)
	role := Role{
		Vpn:                                  resp.Data["vpn"].(string),
		TTL:                                  time.Duration(resp.Data["ttl"].(time.Duration)),
		ACLProfile:                           resp.Data["acl_profile"].(string),
		ClientProfile:                        resp.Data["client_profile"].(string),
		GuaranteedEndpointPermissionOverride: resp.Data["guaranteed_endpoint_permission_override"].(bool),
		UsernamePrefix:                       resp.Data["username_prefix"].(string),
	}
	if role.TTL.String() != pl["ttl"] {
		t.Fatal("TTLs are different, ttl set = " + pl["ttl"].(string) + ", ttl received = " + role.TTL.String())
	}

	if role.Vpn != testVpn() {
		t.Fatal("Vpn disappeared")
	}
	if role.ACLProfile != aclProfile() {
		t.Fatalf("ACL profile disappeared, profile read = %s", resp.Data["acl_profile"].(string))
	}
	if role.ClientProfile != clientProfile() {
		t.Fatal("Client profile disappeared")
	}
	if role.GuaranteedEndpointPermissionOverride != guaranteedEndpointPermissionOverride {
		t.Fatalf("GuaranteedEndpointPermissionOverride received: %t, needed: %t", role.GuaranteedEndpointPermissionOverride, guaranteedEndpointPermissionOverride)
	}
	if role.UsernamePrefix != testUserPrefix {
		t.Fatalf("Received username_prefix: %s, expected: %s", role.UsernamePrefix, testUserPrefix)
	}
}

// TestFetchRoleLegacyFormat tests fetchRole with legacy Role1 format (TTL as string)
func TestFetchRoleLegacyFormat(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Store a role in the legacy format (TTL as string instead of time.Duration)
	legacyRole := map[string]interface{}{
		"Name":          "legacy-role",
		"Vpn":           testVpn(),
		"TTL":           "3600", // Legacy format: TTL as string (seconds)
		"ConfigName":    "default",
		"ACLProfile":    aclProfile(),
		"ClientProfile": clientProfile(),
	}

	entry, err := logical.StorageEntryJSON("roles/legacy-role", legacyRole)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.StorageView.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch the role - should trigger legacy format parsing
	role, err := be.fetchRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, "legacy-role")
	if err != nil {
		t.Fatalf("fetchRole failed: %v", err)
	}
	if role == nil {
		t.Fatal("fetchRole returned nil role")
	}
	if role.Name != "legacy-role" {
		t.Fatalf("Expected role name 'legacy-role', got '%s'", role.Name)
	}
	expectedTTL := time.Duration(3600) * time.Second
	if role.TTL != expectedTTL {
		t.Fatalf("Expected TTL %v, got %v", expectedTTL, role.TTL)
	}
}

// TestFetchRoleInvalidJSON tests fetchRole with invalid JSON that fails both decoders
func TestFetchRoleInvalidJSON(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Store invalid JSON directly in storage
	entry := &logical.StorageEntry{
		Key:   "roles/invalid-role",
		Value: []byte("{invalid json"),
	}
	err := cfg.StorageView.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch should fail with decode error
	_, err = be.fetchRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, "invalid-role")
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestFetchRoleInvalidTTL tests fetchRole with legacy format but invalid TTL string
func TestFetchRoleInvalidTTL(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Store a role in legacy format with invalid TTL
	legacyRole := map[string]interface{}{
		"Name":          "invalid-ttl-role",
		"Vpn":           testVpn(),
		"TTL":           "not-a-number", // Invalid TTL string
		"ConfigName":    "default",
		"ACLProfile":    aclProfile(),
		"ClientProfile": clientProfile(),
	}

	entry, err := logical.StorageEntryJSON("roles/invalid-ttl-role", legacyRole)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.StorageView.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch should fail with parse duration error
	_, err = be.fetchRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, "invalid-ttl-role")
	if err == nil {
		t.Fatal("Expected error for invalid TTL, got nil")
	}
}

// TestFetchRoleNotFound tests fetchRole when role doesn't exist
func TestFetchRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Fetch non-existent role
	role, err := be.fetchRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, "non-existent-role")
	if err != nil {
		t.Fatalf("fetchRole returned error for non-existent role: %v", err)
	}
	if role != nil {
		t.Fatal("Expected nil role for non-existent role, got non-nil")
	}
}
