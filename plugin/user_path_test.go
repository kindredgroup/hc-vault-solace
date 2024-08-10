package solace

import (
	"fmt"
	logical "github.com/hashicorp/vault/sdk/logical"
	"testing"
)

const testUser = "testuser"

var userPayload = map[string]interface{}{
	"role": testRoleName,
}
var userPath = fmt.Sprintf("user/%s", testUser)

func TestReadUser(t *testing.T) {
	b, cfg := getBackend(t)
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	createRole(b, cfg)
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
	userPayload["role"] = nil
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
