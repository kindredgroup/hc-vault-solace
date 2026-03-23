package solace

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

const (
	userPrefix = "testuser"
)

var rotateTestCredsPath = "creds/" + testRoleName

func TestRotateCreds(t *testing.T) {
	b, cfg := getBackend(t)

	validPayload := getValidPayload()
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
	userPayload := getUserPayload()
	resp, err = callBackend(userPath, logical.ReadOperation, userPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	acl := resp.Data["acl_profile"].(string)
	if acl != aclProfile() {
		t.Fatal("Expected ACL profile" + aclProfile() + ", received " + acl)
	}

	// clientProfile is unset, expecting to receive "default" back from Solace
	cp := resp.Data["client_profile"].(string)
	if cp != "default" {
		t.Fatal("Somehow received client profile: " + cp)
	}
	gepo := resp.Data["guaranteed_endpoint_permission_override"].(bool)
	if gepo != guaranteedEndpointPermissionOverride {
		t.Fatalf("Expected GuaranteedEndpointPermissionOverride: %t, received %t", guaranteedEndpointPermissionOverride, gepo)
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

	resp, err = callBackend(fmt.Sprintf("user/%s/%s", testVpn(), user), logical.ReadOperation, pl, b, cfg)

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

	validPayload := getValidPayload()
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
	_, err = callBackend("creds/", logical.RevokeOperation, pl, b, cfg, resp.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(user, userPrefix+"-") {
		t.Fatal("Expected prefix " + userPrefix + ", got username " + user)
	}
}

func TestRotateCredsMissingRole(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/",
		Storage:   cfg.StorageView,
	}

	// FieldData without "role" field set
	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: map[string]*framework.FieldSchema{
			"role":   {Type: framework.TypeString},
			"prefix": {Type: framework.TypeString},
		},
	}

	resp, err := be.rotateCreds(context.Background(), req, data)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("Expected error response for missing role")
	}
	if !strings.Contains(resp.Error().Error(), "Role name is mandatory") {
		t.Fatalf("Expected 'Role name is mandatory' error, got: %v", resp.Error())
	}
}

func TestRotateCredsRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)

	pl := map[string]interface{}{
		"role": "nonexistent-role",
	}
	resp, err := callBackend("creds/nonexistent-role", logical.ReadOperation, pl, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("Expected error response for nonexistent role")
	}
	if !strings.Contains(resp.Error().Error(), "role not found") {
		t.Fatalf("Expected 'role not found' error, got: %v", resp.Error())
	}
}

func TestRotateCredsFetchRoleError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Use errorStorage to simulate storage failure
	mockStorage := &errorStorage{
		Storage: cfg.StorageView,
		failGet: true,
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testrole",
		Storage:   mockStorage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"role": "testrole",
		},
		Schema: map[string]*framework.FieldSchema{
			"role":   {Type: framework.TypeString},
			"prefix": {Type: framework.TypeString},
		},
	}

	resp, err := be.rotateCreds(context.Background(), req, data)
	if err == nil {
		t.Fatal("Expected error from storage failure")
	}
	if !strings.Contains(err.Error(), "simulated Get failure") {
		t.Fatalf("Expected storage error, got: %v", err)
	}
	if resp != nil {
		t.Fatalf("Expected nil response, got: %v", resp)
	}
}

func TestRotateCredsFetchConfigError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Create a role first
	createRole(b, cfg)

	// Use selective error storage that only fails on config lookups
	selectiveStorage := &selectiveErrorStorage{
		Storage:       cfg.StorageView,
		failGetPrefix: confStoragePrefix,
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + testRoleName,
		Storage:   selectiveStorage,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"role": testRoleName,
		},
		Schema: map[string]*framework.FieldSchema{
			"role":   {Type: framework.TypeString},
			"prefix": {Type: framework.TypeString},
		},
	}

	resp, err := be.rotateCreds(context.Background(), req, data)
	if err == nil {
		t.Fatal("Expected error from config fetch failure")
	}
	if !strings.Contains(err.Error(), "simulated Get failure") {
		t.Fatalf("Expected storage error, got: %v", err)
	}
	if resp != nil {
		t.Fatalf("Expected nil response, got: %v", resp)
	}
}

func revokeCreds(b logical.Backend, cfg *logical.BackendConfig, user string, secret *logical.Secret) (*logical.Response, error) {
	pl := map[string]interface{}{
		"username": user,
		"role":     testRoleName,
	}
	return callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)

}

func TestRevokeCredsMissingUsername(t *testing.T) {
	b, cfg := getBackend(t)

	pl := map[string]interface{}{
		"role": testRoleName,
	}
	// Revoke requires a secret with the correct type
	secret := &logical.Secret{
		InternalData: map[string]interface{}{
			"secret_type": SecretType,
		},
	}
	resp, err := callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("Expected error response for missing username")
	}
	if !strings.Contains(resp.Error().Error(), "Username is mandatory") {
		t.Fatalf("Expected 'Username is mandatory' error, got: %v", resp.Error())
	}
}

func TestRevokeCredsMissingRole(t *testing.T) {
	b, cfg := getBackend(t)

	pl := map[string]interface{}{
		"username": "testuser",
	}
	secret := &logical.Secret{
		InternalData: map[string]interface{}{
			"secret_type": SecretType,
		},
	}
	resp, err := callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("Expected error response for missing role")
	}
	if !strings.Contains(resp.Error().Error(), "Role is mandatory") {
		t.Fatalf("Expected 'Role is mandatory' error, got: %v", resp.Error())
	}
}

func TestRevokeCredsRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)

	pl := map[string]interface{}{
		"username": "testuser",
		"role":     "nonexistent-role",
	}
	secret := &logical.Secret{
		InternalData: map[string]interface{}{
			"secret_type": SecretType,
		},
	}
	resp, err := callBackend("creds/", logical.RevokeOperation, pl, b, cfg, secret)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("Expected error response for nonexistent role")
	}
	if !strings.Contains(resp.Error().Error(), "role not found") {
		t.Fatalf("Expected 'role not found' error, got: %v", resp.Error())
	}
}

func TestRevokeCredsFetchRoleError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Use errorStorage to simulate storage failure
	mockStorage := &errorStorage{
		Storage: cfg.StorageView,
		failGet: true,
	}

	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/",
		Storage:   mockStorage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"secret_type": SecretType,
			},
		},
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"username": "testuser",
			"role":     "testrole",
		},
		Schema: map[string]*framework.FieldSchema{
			"username": {Type: framework.TypeString},
			"role":     {Type: framework.TypeString},
		},
	}

	resp, err := be.revokeCreds(context.Background(), req, data)
	if err == nil {
		t.Fatal("Expected error from storage failure")
	}
	if !strings.Contains(err.Error(), "simulated Get failure") {
		t.Fatalf("Expected storage error, got: %v", err)
	}
	if resp != nil {
		t.Fatalf("Expected nil response, got: %v", resp)
	}
}

func TestRevokeCredsFetchConfigError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	// Create a role that references a config
	createRole(b, cfg)

	// Create a selective error storage that only fails on config lookups
	selectiveStorage := &selectiveErrorStorage{
		Storage:       cfg.StorageView,
		failGetPrefix: confStoragePrefix,
	}

	req := &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/",
		Storage:   selectiveStorage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"secret_type": SecretType,
			},
		},
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"username": "testuser",
			"role":     testRoleName,
		},
		Schema: map[string]*framework.FieldSchema{
			"username": {Type: framework.TypeString},
			"role":     {Type: framework.TypeString},
		},
	}

	resp, err := be.revokeCreds(context.Background(), req, data)
	if err == nil {
		t.Fatal("Expected error from config fetch failure")
	}
	if !strings.Contains(err.Error(), "simulated Get failure") {
		t.Fatalf("Expected storage error, got: %v", err)
	}
	if resp != nil {
		t.Fatalf("Expected nil response, got: %v", resp)
	}
}

// selectiveErrorStorage fails Get only for keys with a specific prefix
type selectiveErrorStorage struct {
	logical.Storage
	failGetPrefix string
}

func (s *selectiveErrorStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	if strings.HasPrefix(key, s.failGetPrefix) {
		return nil, fmt.Errorf("simulated Get failure")
	}
	return s.Storage.Get(ctx, key)
}
