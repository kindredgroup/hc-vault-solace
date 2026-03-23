package solace

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
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

// TestListRolesEmpty tests listing roles when none exist
func TestListRolesEmpty(t *testing.T) {
	b, cfg := getBackend(t)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("List failed: %v", resp.Error())
	}

	// Should return empty list or nil keys
	keys, ok := resp.Data["keys"]
	if ok && keys != nil {
		keyList := keys.([]string)
		if len(keyList) > 0 {
			t.Fatalf("Expected empty list, got %d roles", len(keyList))
		}
	}
}

// TestListRolesMultiple tests listing multiple roles
func TestListRolesMultiple(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	// Create multiple roles
	roleNames := []string{"list-role-a", "list-role-b", "list-role-c"}
	for _, roleName := range roleNames {
		pl := map[string]interface{}{
			"name":        roleName,
			"vpn":         testVpn(),
			"ttl":         credTTL,
			"config_name": "default",
			"acl_profile": aclProfile(),
		}
		resp, err := callBackend("roles/"+roleName, logical.CreateOperation, pl, b, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("Failed to create role %s: %v", roleName, resp.Error())
		}
	}

	// List all roles
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("List failed: %v", resp.Error())
	}

	keys, ok := resp.Data["keys"]
	if !ok || keys == nil {
		t.Fatal("Expected keys in response")
	}

	keyList := keys.([]string)
	if len(keyList) < len(roleNames) {
		t.Fatalf("Expected at least %d roles, got %d", len(roleNames), len(keyList))
	}

	// Verify all created roles are in the list
	keyMap := make(map[string]bool)
	for _, k := range keyList {
		keyMap[k] = true
	}
	for _, roleName := range roleNames {
		if !keyMap[roleName] {
			t.Fatalf("Role %s not found in list", roleName)
		}
	}
}

// TestListRolesAfterDelete tests that deleted roles don't appear in list
func TestListRolesAfterDelete(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	// Create a role
	roleName := "delete-from-list-role"
	pl := map[string]interface{}{
		"name":        roleName,
		"vpn":         testVpn(),
		"ttl":         credTTL,
		"config_name": "default",
		"acl_profile": aclProfile(),
	}
	resp, err := callBackend("roles/"+roleName, logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("Failed to create role: %v", resp.Error())
	}

	// Verify role is in list
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"].([]string)
	found := false
	for _, k := range keys {
		if k == roleName {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Role should be in list before deletion")
	}

	// Delete the role
	resp, err = callBackend("roles/"+roleName, logical.DeleteOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify role is no longer in list
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   cfg.StorageView,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["keys"] != nil {
		keys = resp.Data["keys"].([]string)
		for _, k := range keys {
			if k == roleName {
				t.Fatal("Deleted role should not be in list")
			}
		}
	}
}

// errorStorage is a configurable storage that can fail on specific operations
type errorStorage struct {
	logical.Storage
	failGet    bool
	failPut    bool
	failDelete bool
	failList   bool
}

func (e *errorStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if e.failGet {
		return nil, fmt.Errorf("simulated Get failure")
	}
	return e.Storage.Get(ctx, key)
}

func (e *errorStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if e.failPut {
		return fmt.Errorf("simulated Put failure")
	}
	return e.Storage.Put(ctx, entry)
}

func (e *errorStorage) Delete(ctx context.Context, key string) error {
	if e.failDelete {
		return fmt.Errorf("simulated Delete failure")
	}
	return e.Storage.Delete(ctx, key)
}

func (e *errorStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if e.failList {
		return nil, fmt.Errorf("simulated List failure")
	}
	return e.Storage.List(ctx, prefix)
}

// TestListRolesStorageError tests listRoles when storage returns an error
func TestListRolesStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	failStore := &errorStorage{Storage: cfg.StorageView, failList: true}

	_, err := be.listRoles(context.Background(), &logical.Request{Storage: failStore}, nil)
	if err == nil {
		t.Fatal("Expected error from storage failure, got nil")
	}
}

// TestFetchRoleStorageError tests fetchRole when Storage.Get fails
func TestFetchRoleStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	failStore := &errorStorage{Storage: cfg.StorageView, failGet: true}

	_, err := be.fetchRole(context.Background(), &logical.Request{Storage: failStore}, "any-role")
	if err == nil {
		t.Fatal("Expected error from storage Get failure, got nil")
	}
}

// TestCreateRoleStorageError tests createRole when Storage.Put fails
func TestCreateRoleStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	failStore := &errorStorage{Storage: cfg.StorageView, failPut: true}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":        "storage-fail-role",
			"vpn":         testVpn(),
			"ttl":         credTTL,
			"config_name": "default",
		},
		Schema: be.pathRole().Fields,
	}
	resp, err := be.createRole(context.Background(), &logical.Request{Storage: failStore}, data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for storage Put failure")
	}
}

// TestDeleteRoleStorageError tests deleteRole when Storage.Delete fails
func TestDeleteRoleStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// First create a role with normal storage
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Now try to delete with failing storage
	failStore := &errorStorage{Storage: cfg.StorageView, failDelete: true}

	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": testRoleName},
		Schema: be.pathRole().Fields,
	}
	resp, err := be.deleteRole(context.Background(), &logical.Request{Storage: failStore}, data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for storage Delete failure")
	}
}

// TestUpdateRoleStorageError tests updateRole when Storage.Put fails
func TestUpdateRoleStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// First create a role with normal storage
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Now try to update with storage that fails on Put but not Get
	failStore := &errorStorage{Storage: cfg.StorageView, failPut: true}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":            testRoleName,
			"username_prefix": "updated-prefix",
		},
		Schema: be.pathRole().Fields,
	}
	resp, err := be.updateRole(context.Background(), &logical.Request{Storage: failStore}, data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for storage Put failure")
	}
}

// TestRoleExCheckRoleExists tests roleExCheck when role exists
func TestRoleExCheckRoleExists(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Create a role first
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Check if role exists
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": testRoleName},
		Schema: be.pathRole().Fields,
	}
	exists, err := be.roleExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err != nil {
		t.Fatalf("roleExCheck returned error: %v", err)
	}
	if !exists {
		t.Fatal("Expected role to exist, got false")
	}
}

// TestRoleExCheckRoleNotExists tests roleExCheck when role doesn't exist
func TestRoleExCheckRoleNotExists(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Check for non-existent role
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "non-existent-role"},
		Schema: be.pathRole().Fields,
	}
	exists, err := be.roleExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err != nil {
		t.Fatalf("roleExCheck returned error: %v", err)
	}
	if exists {
		t.Fatal("Expected role to not exist, got true")
	}
}

// TestRoleExCheckReadError tests roleExCheck when readRole returns an error
func TestRoleExCheckReadError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Store invalid JSON to trigger readRole error
	entry := &logical.StorageEntry{
		Key:   "roles/corrupted-excheck-role",
		Value: []byte("{invalid json"),
	}
	err := cfg.StorageView.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	// Check for corrupted role
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "corrupted-excheck-role"},
		Schema: be.pathRole().Fields,
	}
	exists, err := be.roleExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err == nil {
		t.Fatal("Expected error from corrupted role, got nil")
	}
	if exists {
		t.Fatal("Expected exists to be false on error")
	}
}

// TestRoleExCheckMissingName tests roleExCheck when name is missing
func TestRoleExCheckMissingName(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Call with empty data (no name)
	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: be.pathRole().Fields,
	}
	exists, err := be.roleExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	// readRole returns error response for missing name, which becomes an error from roleExCheck
	if err == nil {
		t.Fatal("Expected error for missing name")
	}
	if exists {
		t.Fatal("Expected exists to be false on error")
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

// TestCreateRoleMissingVpn tests createRole with missing VPN
func TestCreateRoleMissingVpn(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	pl := map[string]interface{}{
		"name":        "test-role-no-vpn",
		"ttl":         credTTL,
		"config_name": "default",
		// "vpn" is missing
	}
	resp, err := callBackend("roles/test-role-no-vpn", logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing vpn")
	}
}

// TestCreateRoleMissingTTL tests createRole with missing TTL
func TestCreateRoleMissingTTL(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	pl := map[string]interface{}{
		"name":        "test-role-no-ttl",
		"vpn":         testVpn(),
		"config_name": "default",
		// "ttl" is missing (will be 0)
	}
	resp, err := callBackend("roles/test-role-no-ttl", logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing ttl")
	}
}

// TestCreateRoleMissingConfigName tests createRole with missing config_name
func TestCreateRoleMissingConfigName(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	pl := map[string]interface{}{
		"name": "test-role-no-config",
		"vpn":  testVpn(),
		"ttl":  credTTL,
		// "config_name" is missing
	}
	resp, err := callBackend("roles/test-role-no-config", logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing config_name")
	}
}

// TestCreateRoleWithExplicitGEPO tests createRole with explicit guaranteed_endpoint_permission_override
func TestCreateRoleWithExplicitGEPO(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	pl := map[string]interface{}{
		"name":        "test-role-gepo",
		"vpn":         testVpn(),
		"ttl":         credTTL,
		"config_name": "default",
		"guaranteed_endpoint_permission_override": false, // Explicitly set to false
	}
	resp, err := callBackend("roles/test-role-gepo", logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Read the role back and verify GEPO is false
	resp, err = callBackend("roles/test-role-gepo", logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	gepo, ok := resp.Data["guaranteed_endpoint_permission_override"].(bool)
	if !ok {
		t.Fatal("guaranteed_endpoint_permission_override not found in response")
	}
	if gepo != false {
		t.Fatalf("Expected GEPO to be false, got %v", gepo)
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

// TestReadRoleExisting tests reading an existing role
func TestReadRoleExisting(t *testing.T) {
	b, cfg := getBackend(t)

	// Create a role first
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Read the role
	resp, err := callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Read failed: %v", resp.Error())
	}

	// Verify response contains expected fields
	if resp.Data["name"] != testRoleName {
		t.Fatalf("Expected name '%s', got '%s'", testRoleName, resp.Data["name"])
	}
	if resp.Data["vpn"] != testVpn() {
		t.Fatalf("Expected vpn '%s', got '%s'", testVpn(), resp.Data["vpn"])
	}
	if resp.Data["config_name"] != "default" {
		t.Fatalf("Expected config_name 'default', got '%s'", resp.Data["config_name"])
	}
	if resp.Data["acl_profile"] != aclProfile() {
		t.Fatalf("Expected acl_profile '%s', got '%s'", aclProfile(), resp.Data["acl_profile"])
	}
	if resp.Data["username_prefix"] != testUserPrefix {
		t.Fatalf("Expected username_prefix '%s', got '%s'", testUserPrefix, resp.Data["username_prefix"])
	}

	// Verify boolean fields
	if _, ok := resp.Data["guaranteed_endpoint_permission_override"].(bool); !ok {
		t.Fatal("guaranteed_endpoint_permission_override should be a bool")
	}
	if _, ok := resp.Data["subscription_manager"].(bool); !ok {
		t.Fatal("subscription_manager should be a bool")
	}
}

// TestReadRoleMissingName tests readRole with missing name (direct call)
func TestReadRoleMissingName(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Call readRole directly with empty FieldData (no name)
	emptyData := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: be.pathRole().Fields,
	}
	resp, err := be.readRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, emptyData)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing name")
	}
}

// TestReadRoleWithFetchError tests readRole when fetchRole returns an error
func TestReadRoleWithFetchError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Store invalid JSON to trigger fetchRole error
	entry := &logical.StorageEntry{
		Key:   "roles/corrupted-role",
		Value: []byte("{invalid json"),
	}
	err := cfg.StorageView.Put(context.Background(), entry)
	if err != nil {
		t.Fatal(err)
	}

	// Try to read the corrupted role
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "corrupted-role"},
		Schema: be.pathRole().Fields,
	}
	_, err = be.readRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err == nil {
		t.Fatal("Expected error for corrupted role data, got nil")
	}
}

// TestReadRoleAllFields tests that all role fields are returned correctly
func TestReadRoleAllFields(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	// Create a role with all fields set
	pl := map[string]interface{}{
		"name":            "full-role",
		"vpn":             testVpn(),
		"ttl":             3600,
		"config_name":     "default",
		"acl_profile":     aclProfile(),
		"client_profile":  clientProfile(),
		"username_prefix": "fulltest",
		"guaranteed_endpoint_permission_override": false,
		"subscription_manager":                    true,
	}
	resp, err := callBackend("roles/full-role", logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("Create failed: %v", resp.Error())
	}

	// Read and verify all fields
	resp, err = callBackend("roles/full-role", logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}

	// Check all fields
	expectedFields := []string{
		"name", "vpn", "ttl", "config_name", "acl_profile",
		"client_profile", "username_prefix",
		"guaranteed_endpoint_permission_override", "subscription_manager",
	}
	for _, field := range expectedFields {
		if _, ok := resp.Data[field]; !ok {
			t.Fatalf("Missing field '%s' in response", field)
		}
	}

	// Verify specific values
	if resp.Data["client_profile"].(string) != clientProfile() {
		t.Fatalf("Expected client_profile '%s', got '%s'", clientProfile(), resp.Data["client_profile"])
	}
	if resp.Data["subscription_manager"].(bool) != true {
		t.Fatal("Expected subscription_manager to be true")
	}
	if resp.Data["guaranteed_endpoint_permission_override"].(bool) != false {
		t.Fatal("Expected GEPO to be false")
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

// TestDeleteRoleExisting tests deleting an existing role
func TestDeleteRoleExisting(t *testing.T) {
	b, cfg := getBackend(t)

	// Create a role first
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify role exists
	resp, err := callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Role was not created")
	}

	// Delete the role
	resp, err = callBackend(testRolePath, logical.DeleteOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("Delete failed: %v", resp.Error())
	}

	// Verify role no longer exists
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("Role still exists after deletion")
	}
}

// TestDeleteRoleAndRecreate tests deleting and recreating a role
func TestDeleteRoleAndRecreate(t *testing.T) {
	b, cfg := getBackend(t)

	// Create a role
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the role
	resp, err := callBackend(testRolePath, logical.DeleteOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("Delete failed: %v", resp.Error())
	}

	// Recreate the role with different settings
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)
	pl := map[string]interface{}{
		"name":            testRoleName,
		"vpn":             testVpn(),
		"ttl":             100, // Different TTL
		"config_name":     "default",
		"acl_profile":     aclProfile(),
		"username_prefix": "recreated",
	}
	resp, err = callBackend(testRolePath, logical.CreateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Recreate failed: %v", resp.Error())
	}

	// Verify recreated role has new settings
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Role was not recreated")
	}
	if resp.Data["username_prefix"].(string) != "recreated" {
		t.Fatalf("Expected username_prefix 'recreated', got '%s'", resp.Data["username_prefix"].(string))
	}
}

// TestDeleteRoleMultiple tests deleting multiple roles
func TestDeleteRoleMultiple(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	// Create multiple roles
	roles := []string{"delete-test-role1", "delete-test-role2", "delete-test-role3"}
	for _, roleName := range roles {
		pl := map[string]interface{}{
			"name":        roleName,
			"vpn":         testVpn(),
			"ttl":         credTTL,
			"config_name": "default",
			"acl_profile": aclProfile(),
		}
		resp, err := callBackend("roles/"+roleName, logical.CreateOperation, pl, b, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if resp.IsError() {
			t.Fatalf("Failed to create role %s: %v", roleName, resp.Error())
		}
	}

	// Delete each role and verify
	for _, roleName := range roles {
		resp, err := callBackend("roles/"+roleName, logical.DeleteOperation, b, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("Delete failed for %s: %v", roleName, resp.Error())
		}

		// Verify deletion
		resp, err = callBackend("roles/"+roleName, logical.ReadOperation, b, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("Role %s still exists after deletion", roleName)
		}
	}
}

// TestDeleteRoleMissingName tests deleteRole with missing name (direct call)
func TestDeleteRoleMissingName(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Call deleteRole directly with empty FieldData (no name)
	emptyData := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: be.pathRole().Fields,
	}
	resp, err := be.deleteRole(context.Background(), &logical.Request{Storage: cfg.StorageView}, emptyData)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected error response, got nil")
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing name")
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

// TestUpdateRoleNonExistent tests updateRole when role doesn't exist (should create it)
func TestUpdateRoleNonExistent(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
	writeConfig(validPayload, b, cfg)

	pl := map[string]interface{}{
		"name":            "new-role-via-update",
		"vpn":             testVpn(),
		"ttl":             credTTL,
		"config_name":     "default",
		"acl_profile":     aclProfile(),
		"username_prefix": "updatetest",
	}
	resp, err := callBackend("roles/new-role-via-update", logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update (create) failed: %v", resp.Error())
	}

	// Verify role was created
	resp, err = callBackend("roles/new-role-via-update", logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Role was not created via update")
	}
}

// TestUpdateRoleVpn tests updating the VPN field
func TestUpdateRoleVpn(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Update only VPN (using same VPN since we can't create another in test)
	pl := map[string]interface{}{
		"name": testRoleName,
		"vpn":  testVpn(), // Same VPN, but tests the branch
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update VPN failed: %v", resp.Error())
	}
}

// TestUpdateRoleConfigName tests updating the config_name field
func TestUpdateRoleConfigName(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	pl := map[string]interface{}{
		"name":        testRoleName,
		"config_name": "default", // Same config, but tests the branch
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update config_name failed: %v", resp.Error())
	}
}

// TestUpdateRoleUsernamePrefix tests updating the username_prefix field
func TestUpdateRoleUsernamePrefix(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	newPrefix := "newprefix"
	pl := map[string]interface{}{
		"name":            testRoleName,
		"username_prefix": newPrefix,
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update username_prefix failed: %v", resp.Error())
	}

	// Verify the update
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["username_prefix"].(string) != newPrefix {
		t.Fatalf("Expected username_prefix '%s', got '%s'", newPrefix, resp.Data["username_prefix"].(string))
	}
}

// TestUpdateRoleGEPO tests updating guaranteed_endpoint_permission_override
func TestUpdateRoleGEPO(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Update GEPO to false
	pl := map[string]interface{}{
		"name": testRoleName,
		"guaranteed_endpoint_permission_override": false,
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update GEPO failed: %v", resp.Error())
	}

	// Verify the update
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["guaranteed_endpoint_permission_override"].(bool) != false {
		t.Fatal("Expected GEPO to be false after update")
	}
}

// TestUpdateRoleSubscriptionManager tests updating subscription_manager
func TestUpdateRoleSubscriptionManager(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Update subscription_manager to true
	pl := map[string]interface{}{
		"name":                 testRoleName,
		"subscription_manager": true,
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update subscription_manager failed: %v", resp.Error())
	}

	// Verify the update
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["subscription_manager"].(bool) != true {
		t.Fatal("Expected subscription_manager to be true after update")
	}
}

// TestUpdateRoleMultipleFields tests updating multiple fields at once
func TestUpdateRoleMultipleFields(t *testing.T) {
	b, cfg := getBackend(t)
	_, err := createRole(b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	newPrefix := "multiupdate"
	pl := map[string]interface{}{
		"name":                 testRoleName,
		"ttl":                  100,
		"acl_profile":          aclProfile(),
		"client_profile":       clientProfile(),
		"username_prefix":      newPrefix,
		"subscription_manager": true,
		"guaranteed_endpoint_permission_override": false,
	}
	resp, err := callBackend(testRolePath, logical.UpdateOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("Update multiple fields failed: %v", resp.Error())
	}

	// Verify all updates
	resp, err = callBackend(testRolePath, logical.ReadOperation, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["username_prefix"].(string) != newPrefix {
		t.Fatalf("Expected username_prefix '%s', got '%s'", newPrefix, resp.Data["username_prefix"].(string))
	}
	if resp.Data["subscription_manager"].(bool) != true {
		t.Fatal("Expected subscription_manager to be true")
	}
	if resp.Data["guaranteed_endpoint_permission_override"].(bool) != false {
		t.Fatal("Expected GEPO to be false")
	}
	if resp.Data["client_profile"].(string) != clientProfile() {
		t.Fatalf("Expected client_profile '%s', got '%s'", clientProfile(), resp.Data["client_profile"].(string))
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
