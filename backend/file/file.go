// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package file allows to fetch secrets from files
package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/DataDog/datadog-secret-backend/secret"
)

// FileBackendConfig is the configuration for a file backend
type FileBackendConfig struct {
	SecretsPath string `mapstructure:"secrets_path"`
}

// FileBackend represents backend for individual secret files
type FileBackend struct {
	Config FileBackendConfig
}

// NewFileBackend returns a new file backend
func NewFileBackend(bc map[string]interface{}) (*FileBackend, error) {
	backendConfig := FileBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}

	if backendConfig.SecretsPath == "" {
		return nil, fmt.Errorf("secrets_path is required")
	}

	info, err := os.Stat(backendConfig.SecretsPath)
	if err != nil {
		return nil, fmt.Errorf("secrets path '%s' is not accessible: %w", backendConfig.SecretsPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets path '%s' is not a directory", backendConfig.SecretsPath)
	}

	return &FileBackend{Config: backendConfig}, nil
}

// GetSecretOutput retrieves a secret from a file
func (b *FileBackend) GetSecretOutput(_ context.Context, secretString string) secret.Output {
	var path string

	if filepath.IsAbs(secretString) {
		path = secretString
	} else if strings.Contains(secretString, "..") || strings.ContainsAny(secretString, `/\`) {
		es := "invalid secret name: must not contain '..' or path separators"
		return secret.Output{Value: nil, Error: &es}
	} else {
		path = filepath.Join(b.Config.SecretsPath, secretString)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			es := secret.ErrKeyNotFound.Error()
			return secret.Output{Value: nil, Error: &es}
		}
		if os.IsPermission(err) {
			es := fmt.Sprintf("permission denied reading secret '%s'", secretString)
			return secret.Output{Value: nil, Error: &es}
		}
		es := fmt.Sprintf("failed to read secret '%s': %s", secretString, err.Error())
		return secret.Output{Value: nil, Error: &es}
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		es := secret.ErrKeyNotFound.Error()
		return secret.Output{Value: nil, Error: &es}
	}

	return secret.Output{Value: &value, Error: nil}
}
