package solace

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

func getValidPayload() map[string]interface{} {
	return map[string]interface{}{
		"name":        configPath,
		"host":        solaceHost,
		"username":    basicAuthUser(),
		"password":    basicAuthPwd(),
		"disable_tls": true,
	}
}

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

func configData(be *backend, raw map[string]interface{}) *framework.FieldData {
	return &framework.FieldData{Raw: raw, Schema: be.pathSolaceConfig().Fields}
}

func TestListConfigs(t *testing.T) {
	b, cfg := getBackend(t)
	writeConfig(getValidPayload(), b, cfg)
	if !fetchAndCheckOne(t, b, cfg, "configs/", configName) {
		t.Fatal("Config not found: " + configName)
	}
	if fetchAndCheckOne(t, b, cfg, "configs/", wrongConfig) {
		t.Fatal("Config non-existing config found: " + wrongConfig)
	}
}

func TestListConfigsStorageError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	failStore := &errorStorage{Storage: cfg.StorageView, failList: true}
	_, err := be.listConfigs(context.Background(), &logical.Request{Storage: failStore}, nil)
	if err == nil {
		t.Fatal("Expected error from storage List failure, got nil")
	}
}

// TestReadConfigEmptyName exercises the len(cfg.Name) == 0 guard in readConfig.
func TestReadConfigEmptyName(t *testing.T) {
	be, cfg := getTypedBackend(t)

	entry, err := logical.StorageEntryJSON(confStoragePrefix+"/emptyname", &solaceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.StorageView.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	resp, err := be.readConfig(context.Background(), &logical.Request{Storage: cfg.StorageView}, configData(be, map[string]interface{}{"name": "emptyname"}))
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("Expected nil response for config with empty name")
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

// Vault CLI uses logical.UpdateOperation when writing a new config.
func TestUpdateNewConfig(t *testing.T) {
	newConfigTester(t, updateConfig)
}

func newConfigTester(t *testing.T, creater func(payload map[string]interface{}, b logical.Backend, cfg *logical.BackendConfig) error) {
	b, cfg := getBackend(t)
	if err := creater(getValidPayload(), b, cfg); err != nil {
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
	t.Log(conf)
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
	if err := writeConfig(getInvalidPayload(), b, cfg); err == nil {
		t.Fatal("Writing junk config succeeded")
	}
}

func createConfigDirect(t *testing.T, raw map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	be, cfg := getTypedBackend(t)
	return be.createConfig(context.Background(), &logical.Request{Storage: cfg.StorageView}, configData(be, raw))
}

func TestCreateConfigMissingRequiredField(t *testing.T) {
	cases := []struct {
		field   string
		payload map[string]interface{}
	}{
		{"name", map[string]interface{}{"host": solaceHost, "username": basicAuthUser(), "password": basicAuthPwd()}},
		{"host", map[string]interface{}{"name": configName, "username": basicAuthUser(), "password": basicAuthPwd()}},
		{"password", map[string]interface{}{"name": configName, "host": solaceHost, "username": basicAuthUser()}},
	}
	for _, tc := range cases {
		t.Run("missing_"+tc.field, func(t *testing.T) {
			resp, err := createConfigDirect(t, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if !resp.IsError() {
				t.Fatalf("Expected error response for missing %s", tc.field)
			}
		})
	}
}

func TestCreateConfigPersistFailure(t *testing.T) {
	be, cfg := getTypedBackend(t)
	failStore := &errorStorage{Storage: cfg.StorageView, failPut: true}
	raw := map[string]interface{}{
		"name":        configName,
		"host":        solaceHost,
		"username":    basicAuthUser(),
		"password":    basicAuthPwd(),
		"disable_tls": true,
	}
	resp, err := be.createConfig(context.Background(), &logical.Request{Storage: failStore}, configData(be, raw))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response when persist fails")
	}
}

func TestUpdateConfig(t *testing.T) {
	updatedUser := "vaultadmin"

	b, cfg := getBackend(t)
	if err := writeConfig(getValidPayload(), b, cfg); err != nil {
		t.Fatal(err)
	}
	if err := updateConfig(map[string]interface{}{"name": configPath, "username": updatedUser}, b, cfg); err != nil {
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

func TestUpdateConfigFetchError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	failStore := &errorStorage{Storage: cfg.StorageView, failGet: true}
	_, err := be.updateConfig(context.Background(), &logical.Request{Storage: failStore}, configData(be, map[string]interface{}{"name": configName}))
	if err == nil {
		t.Fatal("Expected error from storage Get failure, got nil")
	}
}

func TestUpdateConfigPersistFailure(t *testing.T) {
	be, cfg := getTypedBackend(t)
	if err := writeConfig(getValidPayload(), be, cfg); err != nil {
		t.Fatal(err)
	}
	failStore := &errorStorage{Storage: cfg.StorageView, failPut: true}
	resp, err := be.updateConfig(context.Background(), &logical.Request{Storage: failStore}, configData(be, map[string]interface{}{"name": configName, "username": "newuser"}))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response when persist fails")
	}
}

func TestDeleteConfigMissingName(t *testing.T) {
	be, cfg := getTypedBackend(t)
	resp, err := be.deleteConfig(context.Background(), &logical.Request{Storage: cfg.StorageView}, configData(be, map[string]interface{}{}))
	if err != nil {
		t.Fatalf("Expected nil error, got: %v", err)
	}
	if !resp.IsError() {
		t.Fatal("Expected error response for missing name")
	}
}

func TestDeleteConfigStorageError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	failStore := &errorStorage{Storage: cfg.StorageView, failDelete: true}
	_, err := be.deleteConfig(context.Background(), &logical.Request{Storage: failStore}, configData(be, map[string]interface{}{"name": configName}))
	if err == nil {
		t.Fatal("Expected error from storage Delete failure")
	}
}

func TestPersistConfigStorageError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	failStore := &errorStorage{Storage: cfg.StorageView, failPut: true}
	cfg2 := &solaceConfig{
		Name:       "testconfig",
		SolaceHost: "localhost:8080",
		SolaceUser: "admin",
		SolacePwd:  "admin",
		SolacePath: SolacePrefix,
	}
	if err := be.persistConfig(context.Background(), &logical.Request{Storage: failStore}, cfg2); err == nil {
		t.Fatal("Expected persistConfig to return error on storage Put failure")
	}
}

// TestFetchConfigMissingName uses an empty schema so neither "name" nor "config_name" resolves.
func TestFetchConfigMissingName(t *testing.T) {
	be, cfg := getTypedBackend(t)
	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: map[string]*framework.FieldSchema{},
	}
	_, err := be.fetchConfig(context.Background(), &logical.Request{Storage: cfg.StorageView}, data)
	if err == nil {
		t.Fatal("Expected error when name is missing, got nil")
	}
}

func TestConfExCheck(t *testing.T) {
	be, cfg := getTypedBackend(t)
	if err := writeConfig(getValidPayload(), be, cfg); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		key    string
		expect bool
	}{
		{"exists", configName, true},
		{"not_exists", "non-existent-config", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := be.confExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, configData(be, map[string]interface{}{"name": tc.key}))
			if err != nil {
				t.Fatalf("confExCheck returned error: %v", err)
			}
			if exists != tc.expect {
				t.Fatalf("Expected exists=%v, got %v", tc.expect, exists)
			}
		})
	}
}

func TestConfExCheckReadError(t *testing.T) {
	be, cfg := getTypedBackend(t)
	entry := &logical.StorageEntry{
		Key:   "conf/corrupted-config",
		Value: []byte("{invalid json"),
	}
	if err := cfg.StorageView.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	exists, err := be.confExCheck(context.Background(), &logical.Request{Storage: cfg.StorageView}, configData(be, map[string]interface{}{"name": "corrupted-config"}))
	if err == nil {
		t.Fatal("Expected error from corrupted config, got nil")
	}
	if exists {
		t.Fatal("Expected exists to be false on error")
	}
}

func TestDeleteConfig(t *testing.T) {
	b, cfg := getBackend(t)
	if err := writeConfig(getValidPayload(), b, cfg); err != nil {
		t.Fatal(err)
	}

	if _, err := callBackend(configPath, logical.DeleteOperation, namePayload, b, cfg); err != nil {
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
