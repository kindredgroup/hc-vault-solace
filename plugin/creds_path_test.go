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

func requireErrorResponse(t *testing.T, resp *logical.Response, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatalf("expected error response containing %q, got %v", want, resp)
	}
	if got := resp.Error().Error(); !strings.Contains(got, want) {
		t.Fatalf("error = %q, want it to contain %q", got, want)
	}
}

func requireStorageFailure(t *testing.T, resp *logical.Response, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "simulated Get failure") {
		t.Fatalf("error = %v, want simulated Get failure", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response, got %v", resp)
	}
}

// revokeSecret is the minimal secret Vault needs to route a revoke request to this backend.
func revokeSecret() *logical.Secret {
	return &logical.Secret{InternalData: map[string]interface{}{"secret_type": SecretType}}
}

func revokeTestCreds(b logical.Backend, cfg *logical.BackendConfig, payload map[string]interface{}, secret *logical.Secret) (*logical.Response, error) {
	return callBackend("creds/", logical.RevokeOperation, payload, b, cfg, secret)
}

func rotateCredsWithStorage(be *backend, storage logical.Storage, raw map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{Operation: logical.ReadOperation, Path: rotateTestCredsPath, Storage: storage}
	return be.rotateCreds(context.Background(), req, &framework.FieldData{Raw: raw, Schema: be.pathCreds().Fields})
}

func revokeCredsWithStorage(be *backend, storage logical.Storage, raw map[string]interface{}) (*logical.Response, error) {
	req := &logical.Request{Operation: logical.RevokeOperation, Path: "creds/", Storage: storage, Secret: revokeSecret()}
	return be.revokeCreds(context.Background(), req, &framework.FieldData{Raw: raw, Schema: be.secretCreds().Fields})
}

func rotateTestCreds(t *testing.T, b logical.Backend, cfg *logical.BackendConfig, payload map[string]interface{}) (string, func()) {
	t.Helper()

	resp, err := createRole(b, cfg)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if resp.IsError() {
		t.Fatalf("create role: %v", resp.Error())
	}
	resp, err = callBackend(rotateTestCredsPath, logical.ReadOperation, payload, b, cfg)
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
		resp, err := revokeTestCreds(b, cfg, map[string]interface{}{"username": username, "role": testRoleName}, secret)
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
	username, revoke := rotateTestCreds(t, b, cfg, nil)
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
	username, revoke := rotateTestCreds(t, b, cfg, nil)
	t.Cleanup(revoke)

	if want := testUserPrefix + "-"; !strings.HasPrefix(username, want) {
		t.Errorf("username %q does not start with %q", username, want)
	}
}

func TestRotateCredsUsesRequestUsernamePrefix(t *testing.T) {
	b, cfg := getBackend(t)
	username, revoke := rotateTestCreds(t, b, cfg, map[string]interface{}{"prefix": userPrefix})
	t.Cleanup(revoke)

	if want := userPrefix + "-"; !strings.HasPrefix(username, want) {
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
	username, revoke := rotateTestCreds(t, b, cfg, nil)
	revoke()

	if solaceUserExists(t, b, username) {
		t.Errorf("revoked user %q still exists in Solace", username)
	}
}

// solaceUserExists queries SEMP directly so the check does not depend on the plugin's own read path.
func solaceUserExists(t *testing.T, b logical.Backend, username string) bool {
	t.Helper()
	client, err := getClient(&solaceConfig{SolaceHost: solaceHost, SolacePath: SolacePrefix, DisableTLS: true}, b.Logger())
	if err != nil {
		t.Fatal(err)
	}
	params := all.NewGetMsgVpnClientUsernamesParams()
	params.MsgVpnName = testVpn()
	params.Where = []string{"clientUsername==" + username}
	users, err := client.GetMsgVpnClientUsernames(params, httptransport.BasicAuth(basicAuthUser(), basicAuthPwd()))
	if err != nil {
		t.Fatalf("look up user %q: %v", username, err)
	}
	return len(users.Payload.Data) != 0
}

func TestRotateCredsMissingRole(t *testing.T) {
	be, cfg := getTypedBackend(t)
	resp, err := rotateCredsWithStorage(be, cfg.StorageView, map[string]interface{}{})
	requireErrorResponse(t, resp, err, "role name is required")
}

func TestRotateCredsRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := callBackend("creds/nonexistent-role", logical.ReadOperation, map[string]interface{}{"role": "nonexistent-role"}, b, cfg)
	requireErrorResponse(t, resp, err, "role not found")
}

func TestRotateCredsFetchRoleError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	storage := &errorStorage{Storage: cfg.StorageView, failGet: true}
	resp, err := rotateCredsWithStorage(be, storage, map[string]interface{}{"role": testRoleName})
	requireStorageFailure(t, resp, err)
}

func TestRotateCredsFetchConfigError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	createRole(be, cfg)
	storage := &selectiveErrorStorage{Storage: cfg.StorageView, failGetPrefix: confStoragePrefix}
	resp, err := rotateCredsWithStorage(be, storage, map[string]interface{}{"role": testRoleName})
	requireStorageFailure(t, resp, err)
}

func TestRevokeCredsMissingUsername(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := revokeTestCreds(b, cfg, map[string]interface{}{"role": testRoleName}, revokeSecret())
	requireErrorResponse(t, resp, err, "username is required")
}

func TestRevokeCredsMissingRole(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := revokeTestCreds(b, cfg, map[string]interface{}{"username": testUser}, revokeSecret())
	requireErrorResponse(t, resp, err, "role is required")
}

func TestRevokeCredsRoleNotFound(t *testing.T) {
	b, cfg := getBackend(t)
	resp, err := revokeTestCreds(b, cfg, map[string]interface{}{"username": testUser, "role": "nonexistent-role"}, revokeSecret())
	requireErrorResponse(t, resp, err, "role not found")
}

func TestRevokeCredsFetchRoleError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	storage := &errorStorage{Storage: cfg.StorageView, failGet: true}
	resp, err := revokeCredsWithStorage(be, storage, map[string]interface{}{"username": testUser, "role": testRoleName})
	requireStorageFailure(t, resp, err)
}

func TestRevokeCredsFetchConfigError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	createRole(be, cfg)
	storage := &selectiveErrorStorage{Storage: cfg.StorageView, failGetPrefix: confStoragePrefix}
	resp, err := revokeCredsWithStorage(be, storage, map[string]interface{}{"username": testUser, "role": testRoleName})
	requireStorageFailure(t, resp, err)
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
