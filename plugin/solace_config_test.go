package solace

import (
	"github.com/hashicorp/vault/sdk/framework"
	"strings"
	"testing"
)

const (
	firstPassword  = "fubar"
	secondPassword = "fubaz"
)

func TestToData(t *testing.T) {
	cfg := solaceConfig{
		SolacePwd: firstPassword,
	}
	res := cfg.toData()
	if res["solace_pwd"] != firstPassword {
		t.Fatal("Passwords do not match")
	}

	res = cfg.toData(true)
	if res["solace_pwd"] == firstPassword {
		t.Fatal("Passwordis not mangled")
	}
}

func TestFromData(t *testing.T) {
	d := map[string]interface{}{
		"password": secondPassword,
		"name":     "testConfig",
	}
	fd := &framework.FieldData{
		Raw: d,
	}

	b, _ := getBackend(t)
	var be *backend = b.(*backend)
	for _, v := range be.Paths {
		t.Log(v.Pattern)
		if strings.Contains(v.Pattern, "config/(?P") {
			fd.Schema = v.Fields
		}
	}

	cfg := solaceConfig{}
	cfg.fromData(fd)
	if cfg.SolacePwd != secondPassword {
		t.Log(cfg.String())
		t.Fatal("Passwords do not match, got " + cfg.SolacePwd + ", need " + secondPassword)
	}

	// Check if merge works
	cfg = solaceConfig{
		SolacePwd: firstPassword,
	}
	cfg.fromData(fd)
	if cfg.SolacePwd != secondPassword {
		t.Fatal("Merge: passwords do not match, got " + cfg.SolacePwd + ", need " + secondPassword)
	}

}
