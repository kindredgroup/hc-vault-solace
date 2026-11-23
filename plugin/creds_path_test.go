package solace

import (
	"context"
	"fmt"
	"strings"
	"testing"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
	"kindredgroup.com/solace-plugin/gen/solaceapi/all"
)

const (
	userPrefix = "testuser"
)

var rotateTestCredsPath = "creds/" + testRoleName

func rotateTestCreds(t *testing.T, b logical.Backend, cfg *logical.BackendConfig) (string, func()) {
	t.Helper()

	resp, err := createRole(b, cfg)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("create role: %v", resp.Error())
	}
	resp, err = callBackend(rotateTestCredsPath, logical.ReadOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatalf("rotate credentials: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("rotate credentials: %v", resp.Error())
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("rotate credentials: missing secret")
	}
	username, ok := resp.Data["username"].(string)
	if !ok || username == "" {
		t.Fatal("rotate credentials: missing username")
	}
	secret := resp.Secret
	return username, func() {
		t.Helper()
		resp, err := revokeCreds(b, cfg, username, secret)
		if err != nil {
			t.Fatalf("revoke %q: %v", username, err)
		}
		if resp.IsError() {
			t.Fatalf("revoke %q: %v", username, resp.Error())
		}
	}
}

func rotatedTestUserData(t *testing.T) map[string]interface{} {
	t.Helper()
	b, cfg := getBackend(t)
	username, revoke := rotateTestCreds(t, b, cfg)
	t.Cleanup(revoke)

	resp, err := callBackend("user/"+username, logical.ReadOperation, getUserPayload(), b, cfg)
	if err != nil {
		t.Fatalf("read %q: %v", username, err)
	}
	if resp == nil {
		t.Fatalf("read %q: missing response", username)
	}
	if resp.IsError() {
		t.Fatalf("read %q: %v", username, resp.Error())
	}
	return resp.Data
}

func TestRotateCredsUsesRoleUsernamePrefix(t *testing.T) {
	b, cfg := getBackend(t)
	username, revoke := rotateTestCreds(t, b, cfg)
	t.Cleanup(revoke)

	if want := testUserPrefix + "-"; !strings.HasPrefix(username, want) {
		t.Errorf("username %q does not start with %q", username, want)
	}
}

func TestRotateCredsAppliesRoleACLProfile(t *testing.T) {
	if got, want := rotatedTestUserData(t)["acl_profile"], aclProfile(); got != want {
		t.Errorf("acl_profile = %v, want %q", got, want)
	}
}

func TestRotateCredsUsesDefaultClientProfile(t *testing.T) {
	if got := rotatedTestUserData(t)["client_profile"]; got != "default" {
		t.Errorf("client_profile = %v, want default", got)
	}
}

func TestRotateCredsSetsGuaranteedEndpointPermissionOverride(t *testing.T) {
	if got := rotatedTestUserData(t)["guaranteed_endpoint_permission_override"]; got != guaranteedEndpointPermissionOverride {
		t.Errorf("guaranteed_endpoint_permission_override = %v, want %t", got, guaranteedEndpointPermissionOverride)
	}
}

func TestRevokeCredsRemovesRotatedUser(t *testing.T) {
	b, cfg := getBackend(t)
	username, revoke := rotateTestCreds(t, b, cfg)
	revoke()

	client, err := getClient(&solaceConfig{SolaceHost: solaceHost, SolacePath: SolacePrefix, DisableTLS: true}, b.Logger())
	if err != nil {
		t.Fatal(err)
	}
	params := all.NewGetMsgVpnClientUsernamesParams()
	params.MsgVpnName = testVpn()
	params.Where = []string{"clientUsername==" + username}
	users, err := client.GetMsgVpnClientUsernames(params, httptransport.BasicAuth(basicAuthUser(), basicAuthPwd()))
	if err != nil {
		t.Fatalf("look up revoked user %q: %v", username, err)
	}
	if len(users.Payload.Data) != 0 {
		t.Errorf("revoked user %q still exists in Solace", username)
	}
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
		Raw: map[string]interface{}{},
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
	if !strings.Contains(resp.Error().Error(), "role name is required") {
		t.Fatalf("Expected 'role name is required' error, got: %v", resp.Error())
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
	if !strings.Contains(resp.Error().Error(), "username is required") {
		t.Fatalf("Expected 'username is required' error, got: %v", resp.Error())
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
	if !strings.Contains(resp.Error().Error(), "role is required") {
		t.Fatalf("Expected 'role is required' error, got: %v", resp.Error())
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
