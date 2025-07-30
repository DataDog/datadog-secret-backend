// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package hashicorp allows to fetch secrets from Hashicorp vault service
package hashicorp

import (
	"context"
	"errors"
	"strings"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"
)

// VaultBackendConfig contains the configuration to connect to Hashicorp vault backend
type VaultBackendConfig struct {
	VaultSession VaultSessionBackendConfig `mapstructure:"vault_session"`
	VaultToken   string                    `mapstructure:"vault_token"`
	BackendType  string                    `mapstructure:"backend_type"`
	VaultAddress string                    `mapstructure:"vault_address"`
	SecretPath   string                    `mapstructure:"secret_path"`
	Secrets      []string                  `mapstructure:"secrets"`
	VaultTLS     *VaultTLSConfig           `mapstructure:"vault_tls_config"`
}

// VaultTLSConfig contains the TLS and certificate configuration
type VaultTLSConfig struct {
	CACert     string `mapstructure:"ca_cert"`
	CAPath     string `mapstructure:"ca_path"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	TLSServer  string `mapstructure:"tls_server"`
	Insecure   bool   `mapstructure:"insecure"`
}

// VaultBackend is a backend to fetch secrets from Hashicorp vault
type VaultBackend struct {
	BackendID string
	Config    VaultBackendConfig
	Secret    map[string]string
}

// NewVaultBackend returns a new backend for Hashicorp vault
func NewVaultBackend(backendID string, bc map[string]interface{}) (*VaultBackend, error) {
	backendConfig := VaultBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		log.Error().Err(err).Str("backend_id", backendID).
			Msg("failed to map backend configuration")
		return nil, err
	}

	clientConfig := &api.Config{Address: backendConfig.VaultAddress}

	if backendConfig.VaultTLS != nil {
		tlsConfig := &api.TLSConfig{
			CACert:        backendConfig.VaultTLS.CACert,
			CAPath:        backendConfig.VaultTLS.CAPath,
			ClientCert:    backendConfig.VaultTLS.ClientCert,
			ClientKey:     backendConfig.VaultTLS.ClientKey,
			TLSServerName: backendConfig.VaultTLS.TLSServer,
			Insecure:      backendConfig.VaultTLS.Insecure,
		}
		err := clientConfig.ConfigureTLS(tlsConfig)
		if err != nil {
			log.Error().Err(err).Str("backend_id", backendID).
				Msg("failed to initialize vault tls configuration")
			return nil, err
		}
	}

	client, err := api.NewClient(clientConfig)
	if err != nil {
		log.Error().Err(err).Str("backend_id", backendID).
			Msg("failed to create vault client")
		return nil, err
	}

	authMethod, err := NewVaultConfigFromBackendConfig(backendConfig.VaultSession)
	if err != nil {
		log.Error().Err(err).Str("backend_id", backendID).
			Msg("failed to initialize vault session")
		return nil, err
	}
	if authMethod != nil {
		authInfo, err := client.Auth().Login(context.TODO(), authMethod)
		if err != nil {
			log.Error().Err(err).Str("backend_id", backendID).
				Msg("failed to created auth info")
			return nil, err
		}
		if authInfo == nil {
			log.Error().Err(err).Str("backend_id", backendID).
				Msg("No auth info returned")
			return nil, errors.New("No auth info returned")
		}
	} else if backendConfig.VaultToken != "" {
		client.SetToken(backendConfig.VaultToken)
	} else {
		log.Error().Str("backend_id", backendID).
			Msg("No auth method or token provided")
		return nil, errors.New("No auth method or token provided")
	}

	// KV version detection
	isKVv2 := isKVv2Mount(client, backendConfig.SecretPath)

	readPath := backendConfig.SecretPath
	if isKVv2 {
		// If the mount path is set as /Example/Path, and the secret path is set at /Example/Path/Secret,
		// then we need to query from /Example/Path/data/Secret in kv v2, and /Example/Path/Secret in kv v1.
		readPath = insertDataPath(backendConfig.SecretPath)
	}

	secret, err := client.Logical().Read(readPath)
	if err != nil {
		log.Error().Err(err).Str("backend_id", backendID).
			Str("read_path", readPath).
			Msg("Failed to read secret")
		return nil, err
	}
	if secret == nil {
		log.Error().Str("backend_id", backendID).
			Str("read_path", readPath).
			Msg("Vault returned nil secret")
		return nil, errors.New("vault returned nil secret")
	}

	secretValue := make(map[string]string)
	if backendConfig.SecretPath != "" && len(backendConfig.Secrets) > 0 {
		var dataMap map[string]interface{}
		if isKVv2 {
			if inner, ok := secret.Data["data"].(map[string]interface{}); ok {
				dataMap = inner
			} else {
				log.Warn().Str("backend_id", backendID).
					Msg("Secret data is not in expected format for KV v2")
				return nil, errors.New("secret data is not in expected format for KV v2")
			}
		} else {
			dataMap = secret.Data
		}

		for _, item := range backendConfig.Secrets {
			if dataMap != nil {
				if data, ok := dataMap[item]; ok {
					if strVal, ok := data.(string); ok {
						secretValue[item] = strVal
					} else {
						log.Warn().Str("backend_id", backendID).Str("key", item).
							Msg("Secret value is not a string")
					}
				}
			}
		}
	}

	backend := &VaultBackend{
		BackendID: backendID,
		Config:    backendConfig,
		Secret:    secretValue,
	}
	return backend, nil
}

// GetSecretOutput returns a the value for a specific secret
func (b *VaultBackend) GetSecretOutput(secretKey string) secret.Output {
	if val, ok := b.Secret[secretKey]; ok {
		return secret.Output{Value: &val, Error: nil}
	}
	es := secret.ErrKeyNotFound.Error()

	log.Error().
		Str("backend_id", b.BackendID).
		Str("backend_type", b.Config.BackendType).
		Strs("secrets", b.Config.Secrets).
		Str("secret_path", b.Config.SecretPath).
		Str("secret_key", secretKey).
		Msg("failed to retrieve secrets")
	return secret.Output{Value: nil, Error: &es}
}

func isKVv2Mount(client *api.Client, secretPath string) bool {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false
	}
	mountPrefix := getMountPrefix(secretPath, mounts)
	if mountInfo, ok := mounts[mountPrefix]; ok {
		if mountInfo.Type == "kv" {
			if version, ok := mountInfo.Options["version"]; ok && version == "2" {
				return true
			}
		}
	}
	return false
}

func getMountPrefix(secretPath string, mounts map[string]*api.MountOutput) string {
	path := strings.TrimPrefix(secretPath, "/")
	var bestMatch string
	for mount := range mounts {
		if strings.HasPrefix(path, mount) {
			if len(mount) > len(bestMatch) {
				bestMatch = mount
			}
		}
	}
	return bestMatch
}

func insertDataPath(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '/' {
		path = path[1:]
	}
	if idx := indexFirstSlash(path); idx >= 0 {
		return path[:idx] + "/data" + path[idx:]
	}
	return path + "/data"
}

func indexFirstSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
