package solace

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	logical "github.com/hashicorp/vault/sdk/logical"
)

const (
	SolacePrefix      = "SEMP/v2/config"
	confStoragePrefix = "conf"
)

func (b *backend) pathSolaceConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: `Configuration item/backend name`,
			},
			"host": {
				Type:        framework.TypeString,
				Description: `Host part of the SEMP endpoint`,
			},
			"path": {
				Type:        framework.TypeString,
				Description: `Path of the SEMP endpoint`,
			},
			"username": {
				Type:        framework.TypeString,
				Description: `Solace admin user`,
			},
			"password": {
				Type:        framework.TypeString,
				Description: `Password for Solace admin user`,
			},
			"disable_tls": {
				Type:        framework.TypeBool,
				Description: `Disables TLS for SEMP access`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.readConfig,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.createConfig,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.updateConfig,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.deleteConfig,
			},
		},
		ExistenceCheck: b.confExCheck,
		HelpSynopsis: `Config for specific Solace instance.`,
		HelpDescription: `Config for specific Solace instance. There's 1:1 correspondance between ` +
			`config item and Solace instance.`,
	}
}

func (b *backend) pathConfigList() *framework.Path {
	return &framework.Path{
		Pattern: "configs/",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.listConfigs,
			},
		},
	}
}

func (b *backend) listConfigs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	b.bLock.RLock()
	defer b.bLock.RUnlock()
	confs, err := req.Storage.List(ctx, confStoragePrefix+"/")
	if err != nil {
		logger.Error("listConfigs", err)
		return nil, err
	}
	logger.Debug("listConfigs", "confs", confs)
	return logical.ListResponse(confs), nil
}

func (b *backend) readConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.fetchConfig(ctx, req, data)
	if (err != nil) || (cfg == nil) {
		return nil, err
	}
	// fetchConfig return uninitialized struct if config not found in storage.
	if len(cfg.Name) == 0 {
		return nil, nil
	}
	return &logical.Response{
		Data: cfg.toData(true),
	}, nil
}

func (b *backend) fetchConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*solaceConfig, error) {
	var dummy solaceConfig
	logger := b.Backend.Logger()
	logger.Debug("fetchConfig", "req.Path", req.Path)

	nameRaw, ok := data.GetOk("name")
	if !ok {
		// Certain callers can pass config_name parameter
		nameRaw, ok = data.GetOk("config_name")
		if !ok {
			return nil, errors.New("Name for specific Solace configuration/backend is required")
		}
	}
	name := nameRaw.(string)

	b.bLock.RLock()
	defer b.bLock.RUnlock()
	se, err := req.Storage.Get(ctx, fmt.Sprintf("%s/%s", confStoragePrefix, name))
	if err != nil {
		logger.Error("fetchConfig", "storage entry -> error", err)
		return nil, err
	}
	if se == nil {
		return nil, nil
	}
	err = se.DecodeJSON(&dummy)
	if err != nil {
		logger.Error("fetchConfig", "storage entry decode-> error", err)
	}
	logger.Debug("fetchConfig", "config", dummy)
	return &dummy, err
}

func (b *backend) createConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var solaceCfg solaceConfig
	logger := b.Backend.Logger()
	logger.Debug("writeConfig:", "path", req.Path, "req.Data", req.Data, "field data", data)
	for key := range data.Raw {
		logger.Trace("writeConfig", "key", key, "value", data.Raw[key])
	}
	solaceCfg.fromData(data)
	if len(solaceCfg.Name) == 0 {
		return logical.ErrorResponse("Name for specific configuration/backend is required"), nil
	}

	if len(solaceCfg.SolaceHost) == 0 {
		return logical.ErrorResponse("Solace host is required"), nil
	}

	if len(solaceCfg.SolaceUser) == 0 {
		return logical.ErrorResponse("Solace username is required"), nil
	}

	if len(solaceCfg.SolacePwd) == 0 {
		return logical.ErrorResponse("Solace admin user password is required"), nil
	}

	if len(solaceCfg.SolacePath) == 0 {
		solaceCfg.SolacePath = SolacePrefix
	}
	logger.Trace("createConfig", "persisting config", solaceCfg)
	ok := b.persistConfig(ctx, req, &solaceCfg)
	if !ok {
		return logical.ErrorResponse("Persisting config failed"), nil
	}
	return &logical.Response{
		Data: solaceCfg.toData(true),
	}, nil
}

func (b *backend) updateConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()

	for key := range data.Raw {
		logger.Trace("updateConfig", "key", key, "value", data.Raw[key])
	}

	solaceCfg, err := b.fetchConfig(ctx, req, data)
	if err != nil {
		logger.Debug("updateConfig", "fetch error", err)
		return nil, err
	}
	if solaceCfg == nil {
		logger.Debug("updateConfig: didn't get config from storage, creating")
		return b.createConfig(ctx, req, data)
	}
	solaceCfg.fromData(data)

	logger.Debug("updateConfig", "persisting config = ", solaceCfg)
	ok := b.persistConfig(ctx, req, solaceCfg)
	if !ok {
		return logical.ErrorResponse("Persisting config failed"), nil
	}
	return &logical.Response{
		Data: solaceCfg.toData(true),
	}, nil
}

func (b *backend) deleteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	logger := b.Backend.Logger()
	logger.Debug("handleDelete:", "req.Path", req.Path, "req.Data", req.Data)

	nameRaw, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("Name for specific configuration/backend is required"), nil
	}
	name := nameRaw.(string)

	b.bLock.Lock()
	defer b.bLock.Unlock()
	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", confStoragePrefix, name))
	if err != nil {
		logger.Error("handleDelete:", "name", name, "delete", err)
		return nil, err
	}
	return nil, nil
}

func (b *backend) persistConfig(ctx context.Context, req *logical.Request, cfg *solaceConfig) bool {
	logger := b.Backend.Logger()
	logger.Debug("persistConfig", "config", cfg)
	b.bLock.Lock()
	defer b.bLock.Unlock()
	se, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", confStoragePrefix, cfg.Name), cfg)
	if err != nil {
		logger.Error("persistConfig", "logical.StorageEntryJSON -> error", err)
		return false
	}

	err = req.Storage.Put(ctx, se)
	if err != nil {
		logger.Error("persistConfig:", "req.Storage.Put -> error", err)
		return false
	}
	return true
}

func (b *backend) confExCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	cfg, err := b.fetchConfig(ctx, req, data)
	if err != nil {
		return false, err
	}
	if cfg == nil {
		return false, nil
	}
	return true, nil
}
