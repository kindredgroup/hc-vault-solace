package solace

import (
	"context"
	"errors"
	"fmt"

	log "github.com/hashicorp/go-hclog"
	logical "github.com/hashicorp/vault/sdk/logical"
	"testing"
)

// Constants and common functions/helpers for tests
const (
	// First hostname does not have Solace responding
	solaceHost = "localhost,localhost:8090"
	//        solacePath = "SEMP/v2/config"
	solacePath    = ""
	basicAuthUser = "gotest"
	basicAuthPwd  = "test123"
	expectedVpns  = 2

	testVpn       = "testvpn0"
	testPassword  = "changeoninstall"
	testUsername  = "testCclient0"
	aclProfile    = "test_acl_profile"
	clientProfile = "test_client_profile"

	testUserPath = "user/testvpn0/testclient0"
	configPath   = "config/default"
	logLevel     = "info"
)

// getBackend initializes and returns test backend & config.
// Factory() can fail. Callers from tests will pass *testing.T, rest is expected to check if
// getBackend returns nil
func getBackend(vars ...interface{}) (logical.Backend, *logical.BackendConfig) {
	var t *testing.T
	if len(vars) == 1 {
		t = vars[0].(*testing.T)
	}
	cf := logical.TestBackendConfig()
	cf.StorageView = new(logical.InmemStorage)

	cf.Logger = log.Default()
	cf.Logger.SetLevel(log.LevelFromString(logLevel))

	cf.System = &logical.StaticSystemView{}
	ctx := context.Background()

	b, err := Factory(ctx, cf)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		log.New(&log.LoggerOptions{}).Error("Error from SolaceFactory", "error", err)
	}
	return b, cf
}

// callBackend is a helper function that calls specific paths in the plugin.
// optional vars: data: map[string]interface{}, b: logical.Backend, cfg: *logical.BackendConfig
// possible usages:
// callBackend(path, op),
// callBackend(path, op, data),
// callBackend(path, op, backend, backendConfig)
// callBackend(path, op, data, backend, backendConfig)
// callBackend(path, op, data, backend, backendConfig, secret)
func callBackend(path string, op logical.Operation, vars ...interface{}) (*logical.Response, error) {
	var b logical.Backend
	var cfg *logical.BackendConfig
	var d map[string]interface{}
	var s *logical.Secret

	if len(vars) > 0 {
		for _, v := range vars {
			switch t := v.(type) {
			case *logical.BackendConfig:
				cfg = v.(*logical.BackendConfig)
			case logical.Backend:
				b = v.(logical.Backend)
			case map[string]interface{}:
				d = v.(map[string]interface{})
			case *logical.Secret:
				s = v.(*logical.Secret)
			default:
				return nil, fmt.Errorf("Wrong type of argument: %s", t)
			}
		}
	} else if len(vars) > 3 {
		return nil, fmt.Errorf("Wrong number of arguments: %d", len(vars))
	}
	if b == nil || cfg == nil {
		b, cfg = getBackend()
		if b == nil {
			return nil, errors.New("Backend initialization failed")
		}
	}

	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      d,
		Storage:   cfg.StorageView,
		Secret:    s,
	})
}
