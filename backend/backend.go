// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package backend aggregates all supported backends and allow fetching secrets from them
package backend

import (
	"fmt"

	"github.com/DataDog/datadog-secret-backend/backend/akeyless"
	"github.com/DataDog/datadog-secret-backend/backend/aws"
	"github.com/DataDog/datadog-secret-backend/backend/azure"
	"github.com/DataDog/datadog-secret-backend/backend/file"
	"github.com/DataDog/datadog-secret-backend/backend/hashicorp"
	"github.com/DataDog/datadog-secret-backend/secret"
)

// Interface represents the common interface for the secret backends
type Interface interface {
	GetSecretOutput(string) secret.Output
}

// Backend encapsulate all known backends
type Backend struct {
	Backend Interface
}

// InitBackend initialize the backend based on their configuration
func (b *Backend) InitBackend(backendType string, backendConfig map[string]interface{}) {
	backendConfig["backend_type"] = backendType
	switch backendType {
	case "aws.secrets":
		backend, err := aws.NewSecretsManagerBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "aws.ssm":
		backend, err := aws.NewSSMParameterStoreBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "azure.keyvault":
		backend, err := azure.NewKeyVaultBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "hashicorp.vault":
		backend, err := hashicorp.NewVaultBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "file.yaml":
		backend, err := file.NewYAMLBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "file.json":
		backend, err := file.NewJSONBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	case "akeyless":
		backend, err := akeyless.NewAkeylessBackend(backendConfig)
		if err != nil {
			b.Backend = NewErrorBackend(err)
		} else {
			b.Backend = backend
		}
	default:
		b.Backend = &ErrorBackend{
			Error: fmt.Errorf("unsupported backend type: %s", backendType),
		}
	}
}

// GetSecretOutputs returns a the value for a list of given secrets of form "<secret key>"
func (b *Backend) GetSecretOutputs(secrets []string) map[string]secret.Output {
	secretOutputs := make(map[string]secret.Output, 0)
	for _, secretKey := range secrets {
		secretOutputs[secretKey] = b.Backend.GetSecretOutput(secretKey)
	}
	return secretOutputs
}
