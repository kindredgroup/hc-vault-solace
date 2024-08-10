package solace

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

const (
	solaceTypeName = "solace"
	pluginVersion  = "v0.0.52"
)

// Factory creates and configures backend for the plugin main method.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        solaceHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/",
				"role/",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathSolaceConfig(),
				b.pathCreds(),
				b.pathRole(),
				b.pathUser(),
				b.pathRoleList(),
				b.pathConfigList(),
			},
		),
		Secrets: []*framework.Secret{
			b.secretCreds(),
		},
		RunningVersion: pluginVersion,
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)
	logger := b.Backend.Logger()
	logger.Debug("SolaceFactory", "paths", b.Backend.Paths)

	return b, nil
}

type backend struct {
	*framework.Backend
	config solaceConfig
	// Locks access to the Vault. Solace is believed to be able to handle concurrent requests.
	bLock sync.RWMutex
}

const solaceHelp = `
Solace secrets engine manages credentials in Solace boxes/VMRs.
`
