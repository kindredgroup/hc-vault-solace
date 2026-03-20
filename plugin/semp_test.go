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
	validPayload := getValidPayload()
	// Use two hosts to test failover logic - first is a fake port, second is the real container
	validPayload["host"] = "localhost:9999," + solaceHost
	err := writeConfig(validPayload, b, cfg)
	if err != nil {
		t.Error(err)
	}
	createRole(b, cfg)
	userPath := fmt.Sprintf("user/%s", testUser)
	// We expect CallBackend() to fail if something goes wrong with the SEMP client configuration
	resp, err := callBackend(userPath, logical.CreateOperation, getUserPayload(), b, cfg)
	if err != nil {
		t.Error(err)
	}
	if resp == nil {
		t.Fatal("No response!")
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Cleanup
	_, err = callBackend(userPath, logical.DeleteOperation, getUserPayload(), b, cfg)
	if err != nil {
		t.Error(err)
	}

}

func TestIsActive(t *testing.T) {
	cfg := &solaceConfig{
		SolaceHost: solaceHost,
		SolacePath: "",
		SolaceUser: basicAuthUser(),
		SolacePwd:  basicAuthPwd(),
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

func TestGetSchemes(t *testing.T) {
	tests := []struct {
		name       string
		disableTLS bool
		want       []string
	}{
		{
			name:       "TLS enabled",
			disableTLS: false,
			want:       []string{"http", "https"},
		},
		{
			name:       "TLS disabled",
			disableTLS: true,
			want:       []string{"http"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &solaceConfig{DisableTLS: tt.disableTLS}
			got := getSchemes(cfg)
			if len(got) != len(tt.want) {
				t.Errorf("getSchemes() = %v, want %v", got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("getSchemes()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name       string
		disableTLS bool
		want       string
	}{
		{
			name:       "TLS enabled",
			disableTLS: false,
			want:       "https",
		},
		{
			name:       "TLS disabled",
			disableTLS: true,
			want:       "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &solaceConfig{DisableTLS: tt.disableTLS}
			got := getScheme(cfg)
			if got != tt.want {
				t.Errorf("getScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}
