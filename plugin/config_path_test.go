package solace

import (
	"strings"
	"testing"

	logical "github.com/hashicorp/vault/sdk/logical"
)

var validPayload = map[string]interface{}{
	"name":        configPath,
	"host":        solaceHost,
	"username":    basicAuthUser,
	"password":    basicAuthPwd,
	"disable_tls": true,
}

var invalidPayload = map[string]interface{}{
	"host":     solaceHost,
	"password": basicAuthPwd,
}

var namePayload = map[string]interface{}{
	"name": configPath,
}

const (
	wrongConfig = "does not exist"
	mangledPwd  = "***"
)

var configName = strings.Split(configPath, "/")[1]

func TestListConfigs(t *testing.T) {
	b, cfg := getBackend(t)
	writeConfig(validPayload, b, cfg)
	if !fetchAndCheckOne(t, b, cfg, "configs/", configName) {
		t.Fatal("Config not found: " + configName)
	}
	if fetchAndCheckOne(t, b, cfg, "configs/", wrongConfig) {
		t.Fatal("Config non-existing config found: " + wrongConfig)
	}
}

func TestConfigRead(t *testing.T) {
	resp, err := callBackend(configPath, logical.ReadOperation, map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp != nil {
		t.Log(resp)
		t.Fatal("Got response, expected nil!")
	}
}

func TestUnknownRead(t *testing.T) {
	_, err := callBackend(wrongConfig, logical.ReadOperation, nil)
	if err == nil {
		t.Fatal(err)
	} else {
		t.Log(err)
	}
}

func writeConfig(payload map[string]interface{}, b logical.Backend, cfg *logical.BackendConfig) error {
	resp, err := callBackend(configPath, logical.CreateOperation, payload, b, cfg)
	if resp.IsError() {
		return resp.Error()
	}
	return err
}

func updateConfig(payload map[string]interface{}, b logical.Backend, cfg *logical.BackendConfig) error {
	resp, err := callBackend(configPath, logical.UpdateOperation, payload, b, cfg)
	if resp.IsError() {
		return resp.Error()
	}
	return err
}

func TestWriteConfig(t *testing.T) {
	newConfigTester(t, writeConfig)
}

// Vault CLI seems to use logical.UpdateOperation when writing new config.
func TestUpdateNewConfig(t *testing.T) {
	newConfigTester(t, updateConfig)
}

func newConfigTester(t *testing.T, creater func(payload map[string]interface{}, b logical.Backend, cfg *logical.BackendConfig) error) {
	b, cfg := getBackend(t)
	err := creater(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := callBackend(configPath, logical.ReadOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	conf := resp.Data
	t.Log(resp.Data)
	if conf["name"] != configName {
		t.Fatal("Got name = " + conf["name"].(string) + ", need " + configPath)
	}
	if conf["solace_host"] != solaceHost {
		t.Fatal("Got host = " + conf["solace_host"].(string) + ", need " + solaceHost)
	}
	if conf["solace_user"].(string) != basicAuthUser {
		t.Fatal("Got username = " + conf["solace_user"].(string) + ", need " + basicAuthUser)
	}
	if conf["solace_pwd"].(string) != mangledPwd {
		t.Fatal("Got password = " + conf["solace_pwd"].(string) + ", need " + basicAuthPwd)
	}
	if conf["solace_path"].(string) != SolacePrefix {
		t.Fatal("Got path = " + conf["solace_path"].(string) + ", need " + SolacePrefix)
	}

}

func TestWriteJunkConfig(t *testing.T) {
	b, cfg := getBackend(t)
	err := writeConfig(invalidPayload, b, cfg)
	if err == nil {
		t.Fatal("Writing junk config succeeded")
	}
}

func TestUpdateConfig(t *testing.T) {
	updatedUser := "vaultadmin"

	b, cfg := getBackend(t)
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	updatePayload := map[string]interface{}{
		"name":     configPath,
		"username": updatedUser,
	}
	err = updateConfig(updatePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := callBackend(configPath, logical.ReadOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp.Data["solace_user"] != updatedUser {
		t.Fatal("Got user = " + resp.Data["solace_user"].(string) + ", need " + updatedUser)
	}
}
func TestDeleteConfig(t *testing.T) {
	b, cfg := getBackend(t)
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = callBackend(configPath, logical.DeleteOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := callBackend(configPath, logical.ReadOperation, namePayload, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	if resp != nil {
		t.Log(resp.Data)
		t.Fatal("Got response, expected nil")
	}
}
