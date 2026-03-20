package solace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	log "github.com/hashicorp/go-hclog"
	logical "github.com/hashicorp/vault/sdk/logical"
)

// Package-level variables for test configuration (set by TestMain)
var (
	// solaceHost is dynamically set from the testcontainer
	solaceHost string
	// Test fixtures loaded from container setup
	testFixtures *TestFixtures
	// Container reference for cleanup
	testContainer *SolaceContainer
)

// Constants that don't change
const (
	solacePath   = ""
	testPassword = "changeoninstall"
	testUsername = "testCclient0"

	testUserPath = "user/testvpn0/testclient0"
	configPath   = "config/default"
	logLevel     = "info"
)

// Computed values from fixtures (set after TestMain)
func basicAuthUser() string { return testFixtures.AdminUser }
func basicAuthPwd() string  { return testFixtures.AdminPwd }
func testVpn() string       { return testFixtures.VPNName }
func aclProfile() string    { return testFixtures.ACLProfile }
func clientProfile() string { return testFixtures.ClientProfile }

// TestMain sets up the Solace testcontainer and fixtures before running tests
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Check if Docker is available - if not, we can't run integration tests
	if SkipIfNoDocker() {
		fmt.Fprintln(os.Stderr, "Docker/Podman not available, skipping integration tests")
		fmt.Fprintln(os.Stderr, "Set SKIP_DOCKER_TESTS=1 to silence this message")
		os.Exit(0)
	}

	// Start Solace container
	var err error
	testContainer, err = StartSolaceContainer(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Solace container: %v\n", err)
		os.Exit(1)
	}

	// Set up dynamic connection info
	solaceHost = testContainer.Host

	// Create test fixtures (VPN, profiles, etc.)
	testFixtures, err = SetupTestFixtures(testContainer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup test fixtures: %v\n", err)
		testContainer.Terminate(ctx)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	testContainer.Terminate(ctx)

	os.Exit(code)
}

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
