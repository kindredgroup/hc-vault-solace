package solace

import (
	"fmt"
	"testing"

	log "github.com/hashicorp/go-hclog"
	logical "github.com/hashicorp/vault/sdk/logical"
)

func TestGetClientFail(t *testing.T) {
	cfg := &solaceConfig{
		SolaceHost: "does.not.exist, another.fake.host",
	}
	cl, err := getClient(cfg, log.Default())
	if cl != nil {
		t.Error("non-existing host: got back client")
	}
	if err == nil {
		t.Error("non-existing host: err != nil")
	}
}

func TestGetClient(t *testing.T) {
	b, cfg := getBackend(t)
	validPayload["host"] = "localhost:8080,localhost:8090"
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Error(err)
	}
	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", testUser)
	// We expect CallBackend() to fail if something goes wrong with the SEMP client configuration
	resp, err := callBackend(userPath, logical.CreateOperation, userPayload, b, cfg)
	if err != nil {
		t.Error(err)
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	validPayload["host"] = solaceHost

	// Cleanup
	_, err = callBackend(userPath, logical.DeleteOperation, userPayload, b, cfg)
	if err != nil {
		t.Error(err)
	}

}

func TestIsActive(t *testing.T) {
	cfg := &solaceConfig{
		SolaceHost: "localhost:8090",
		SolacePath: "",
		SolaceUser: basicAuthUser,
		SolacePwd:  basicAuthPwd,
		DisableTLS: true,
	}
	b, _ := getBackend(t)
	r := isActive(cfg.SolaceHost, cfg, b.Logger())
	if !r {
		t.Fatal("Message spool is not enabled?")
	}
	cfg.DisableTLS = false
	cfg.SolaceHost = "localhost"
	r = isActive(cfg.SolaceHost, cfg, b.Logger())
	if r {
		t.Fatal("This should have failed on local dev env")
	}
	cfg.SolaceHost = ""
	r = isActive("", cfg, b.Logger())
	if r {
		t.Fatal("No host, should have failed")
	}
}
