package solace

import (
	"github.com/hashicorp/vault/sdk/framework"
	"strings"
	"testing"
)

func TestRole(t *testing.T) {
	b, _ := getBackend(t)
	var be *backend = b.(*backend)
	data := map[string]interface{}{
		"name": testRoleName,
		"vpn":  testVpn,
	}
	input := &framework.FieldData{
		Raw: data,
	}
	for _, v := range be.Paths {
		t.Log(v.Pattern)
		if strings.Contains(v.Pattern, "roles/(?P") {
			input.Schema = v.Fields
		}
	}
	rl, err := data2role(input)
	if err != nil {
		t.Log(err)
		t.Fatal("Correct input failed")
	}
	if rl.Vpn != testVpn {
		t.Fatal("Vpn names differ: sent " + testVpn + ", received" + rl.Vpn)
	}

	input.Raw["name"] = nil
	_, err = data2role(input)
	if err == nil {
		t.Fatal("Zero-length role name is ok!")
	}

	delete(input.Raw, "name")
	_, err = data2role(input)
	if err == nil {
		t.Fatal("Missing role name is ok!")
	}
}
