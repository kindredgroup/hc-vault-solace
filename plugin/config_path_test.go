package solace

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

// getValidPayload returns a fresh payload map with current test config values
func getValidPayload() map[string]interface{} {
	return map[string]interface{}{
		"name":        configPath,
		"host":        solaceHost,
		"username":    basicAuthUser(),
		"password":    basicAuthPwd(),
		"disable_tls": true,
	}
}

// getInvalidPayload returns an invalid payload for testing
func getInvalidPayload() map[string]interface{} {
	return map[string]interface{}{
		"host":     solaceHost,
		"password": basicAuthPwd(),
	}
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
	validPayload := getValidPayload()
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
	validPayload := getValidPayload()
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
	if conf["solace_user"].(string) != basicAuthUser() {
		t.Fatal("Got username = " + conf["solace_user"].(string) + ", need " + basicAuthUser())
	}
	if conf["solace_pwd"].(string) != mangledPwd {
		t.Fatal("Got password = " + conf["solace_pwd"].(string) + ", need " + basicAuthPwd())
	}
	if conf["solace_path"].(string) != SolacePrefix {
		t.Fatal("Got path = " + conf["solace_path"].(string) + ", need " + SolacePrefix)
	}

}

func TestWriteJunkConfig(t *testing.T) {
	b, cfg := getBackend(t)
	invalidPayload := getInvalidPayload()
	err := writeConfig(invalidPayload, b, cfg)
	if err == nil {
		t.Fatal("Writing junk config succeeded")
	}
}

func TestUpdateConfig(t *testing.T) {
	updatedUser := "vaultadmin"

	b, cfg := getBackend(t)
	validPayload := getValidPayload()
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
func TestDeleteConfigMissingName(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: be.pathSolaceConfig().Fields,
	}
	resp, err := be.deleteConfig(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err != nil {
		t.Fatalf("Expected nil error, got: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing name")
	}
}

func TestDeleteConfigStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	storage := &errorStorage{Storage: cfg.StorageView, failDelete: true}
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": configName},
		Schema: be.pathSolaceConfig().Fields,
	}
	_, err := be.deleteConfig(context.Background(), &logical.Request{Storage: storage}, data)
	if err == nil {
		t.Fatal("Expected error from storage Delete failure")
	}
}

func TestPersistConfigStorageError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	storage := &errorStorage{Storage: cfg.StorageView, failPut: true}
	req := &logical.Request{Storage: storage}
	cfg2 := &solaceConfig{
		Name:       "testconfig",
		SolaceHost: "localhost:8080",
		SolaceUser: "admin",
		SolacePwd:  "admin",
		SolacePath: SolacePrefix,
	}

	ok := be.persistConfig(context.Background(), req, cfg2)
	if ok {
		t.Fatal("Expected persistConfig to return false on storage Put error")
	}
}

func TestConfExCheckConfigExists(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	err := writeConfig(getValidPayload(), b, cfg)
	if err != nil {
		t.Fatal(err)
	}

	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": configName},
		Schema: be.pathSolaceConfig().Fields,
	}
	exists, err := be.confExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err != nil {
		t.Fatalf("confExCheck returned error: %v", err)
	}
	if !exists {
		t.Fatal("Expected config to exist, got false")
	}
}

func TestConfExCheckConfigNotExists(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "non-existent-config"},
		Schema: be.pathSolaceConfig().Fields,
	}
	exists, err := be.confExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err != nil {
		t.Fatalf("confExCheck returned error: %v", err)
	}
	if exists {
		t.Fatal("Expected config to not exist, got true")
	}
}

func TestConfExCheckReadError(t *testing.T) {
	b, cfg := getBackend(t)
	be := b.(*backend)

	entry := &logical.StorageEntry{
		Key:   "conf/corrupted-config",
		Value: []byte("{invalid json"),
	}
	if err := cfg.StorageView.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "corrupted-config"},
		Schema: be.pathSolaceConfig().Fields,
	}
	exists, err := be.confExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err == nil {
		t.Fatal("Expected error from corrupted config, got nil")
	}
	if exists {
		t.Fatal("Expected exists to be false on error")
	}
}

func TestDeleteConfig(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload := getValidPayload()
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
