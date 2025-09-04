// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package file

import (
	"fmt"
	"os"

	yaml "gopkg.in/yaml.v2"

	"github.com/mitchellh/mapstructure"

	"github.com/DataDog/datadog-secret-backend/secret"
)

// YamlBackendConfig is the configuration for a YAML backend
type YamlBackendConfig struct {
	FilePath string `mapstructure:"file_path"`
}

// YamlBackend represents backend for YAML file
type YamlBackend struct {
	Config YamlBackendConfig
	Secret map[string]string
}

// NewYAMLBackend returns a new YAML backend
func NewYAMLBackend(bc map[string]interface{}) (
	*YamlBackend, error) {

	backendConfig := YamlBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}

	content, err := os.ReadFile(backendConfig.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml secret file '%s': %s", backendConfig.FilePath, err)
	}

	secretValue := make(map[string]string, 0)
	if err := yaml.Unmarshal(content, secretValue); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml secret from '%s': %s", backendConfig.FilePath, err)
	}

	backend := &YamlBackend{
		Config: backendConfig,
		Secret: secretValue,
	}
	return backend, nil
}

// GetSecretOutput returns a the value for a specific secret
func (b *YamlBackend) GetSecretOutput(secretKey string) secret.Output {
	if val, ok := b.Secret[secretKey]; ok {
		return secret.Output{Value: &val, Error: nil}
	}
	es := secret.ErrKeyNotFound.Error()
	return secret.Output{Value: nil, Error: &es}
}
