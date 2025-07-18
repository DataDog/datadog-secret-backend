// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package file allows to fetch secrets from JSON and YAML files
package file

import (
	"encoding/json"
	"os"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog/log"

	"github.com/DataDog/datadog-secret-backend/secret"
)

// JSONBackendConfig is the configuration for a JSON backend
type JSONBackendConfig struct {
	BackendType string `mapstructure:"backend_type"`
	FilePath    string `mapstructure:"file_path"`
}

// JSONBackend represents backend for JSON file
type JSONBackend struct {
	Config JSONBackendConfig
	Secret map[string]string
}

// NewJSONBackend returns a new JSON backend
func NewJSONBackend(bc map[string]interface{}) (
	*JSONBackend, error) {

	backendConfig := JSONBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		log.Error().Err(err).
			Msg("failed to map backend configuration")
		return nil, err
	}

	content, err := os.ReadFile(backendConfig.FilePath)
	if err != nil {
		log.Error().Err(err).Str("file_path", backendConfig.FilePath).
			Msg("failed to read json secret file")
		return nil, err
	}

	secretValue := make(map[string]string, 0)
	if err := json.Unmarshal(content, &secretValue); err != nil {
		log.Error().Err(err).Str("file_path", backendConfig.FilePath).
			Msg("failed to unmarshal json secret")
		return nil, err
	}

	backend := &JSONBackend{
		Config: backendConfig,
		Secret: secretValue,
	}
	return backend, nil
}

// GetSecretOutput returns a the value for a specific secret
func (b *JSONBackend) GetSecretOutput(secretKey string) secret.Output {
	if val, ok := b.Secret[secretKey]; ok {
		return secret.Output{Value: &val, Error: nil}
	}
	es := secret.ErrKeyNotFound.Error()

	log.Error().
		Str("backend_type", b.Config.BackendType).
		Str("file_path", b.Config.FilePath).
		Str("secret_key", secretKey).
		Msg(es)
	return secret.Output{Value: nil, Error: &es}
}
