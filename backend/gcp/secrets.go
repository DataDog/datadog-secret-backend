// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package gcp allows to fetch secrets from GCP Secret Manager service
package gcp

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/mitchellh/mapstructure"
)

// SessionBackendConfig is the configuration for GCP session
type SessionBackendConfig struct {
	ProjectID string `mapstructure:"project_id"`
}

// SecretManagerBackendConfig is the configuration for GCP Secret Manager backend
type SecretManagerBackendConfig struct {
	Session SessionBackendConfig `mapstructure:"gcp_session"`
}

// SecretManagerBackend represents backend for GCP Secret Manager
type SecretManagerBackend struct {
	Config SecretManagerBackendConfig
	Client *secretmanager.Client
}

// NewSecretManagerBackend returns a new GCP Secret Manager backend
func NewSecretManagerBackend(bc map[string]interface{}) (*SecretManagerBackend, error) {
	backendConfig := SecretManagerBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %v", err)
	}

	return &SecretManagerBackend{
		Config: backendConfig,
		Client: client,
	}, nil
}

func (b *SecretManagerBackend) GetSecretOutput(secretString string) secret.Output {
	return secret.Output{}
}
