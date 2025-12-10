// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package docker allows to fetch secrets from Docker Secrets (Swarm and Compose)
package docker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/DataDog/datadog-secret-backend/secret"
)

// SecretsBackendConfig is the configuration for a Docker Secrets backend
type SecretsBackendConfig struct {
	SecretsPath string `mapstructure:"secrets_path"` // optional
}

// SecretsBackend represents backend for Docker Secrets
type SecretsBackend struct {
	Config SecretsBackendConfig
}

// NewSecretsBackend returns a new Docker Secrets backend
func NewSecretsBackend(bc map[string]interface{}) (*SecretsBackend, error) {
	backendConfig := SecretsBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}

	// https://docs.docker.com/engine/swarm/secrets#how-docker-manages-secrets
	// https://docs.docker.com/compose/how-tos/use-secrets/#use-secrets
	if backendConfig.SecretsPath == "" {
		if runtime.GOOS == "windows" {
			backendConfig.SecretsPath = `C:\ProgramData\Docker\secrets`
		} else {
			backendConfig.SecretsPath = "/run/secrets"
		}
	}

	info, err := os.Stat(backendConfig.SecretsPath)
	if err != nil {
		return nil, fmt.Errorf("secrets path '%s' is not accessible: %w", backendConfig.SecretsPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets path '%s' is not a directory", backendConfig.SecretsPath)
	}

	return &SecretsBackend{Config: backendConfig}, nil
}

// GetSecretOutput retrieves a secret from Docker Secrets
func (b *SecretsBackend) GetSecretOutput(_ context.Context, secretString string) secret.Output {
	var path string

	if filepath.IsAbs(secretString) {
		// target support https://docs.docker.com/engine/swarm/secrets/#intermediate-example-use-secrets-with-a-nginx-service:~:text=location%20using%20the-,target,-option.%20The%20example
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
