// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package gcp allows to fetch secrets from GCP Secret Manager service
package gcp

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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

	client, err := secretmanager.NewClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %v", err)
	}

	return &SecretManagerBackend{
		Config: backendConfig,
		Client: client,
	}, nil
}

func (b *SecretManagerBackend) GetSecretOutput(secretString string) secret.Output {
	// "secret-name" or "secret-name;version"
	sec, version := secretString, "latest"
	if name, ver, ok := strings.Cut(secretString, ";"); ok {
		sec, version = name, ver
	}

	// projects/{project}/secrets/{secret}/versions/{version}
	resource := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", b.Config.Session.ProjectID, sec, version)

	ctx := context.Background()
	req := &secretmanagerpb.AccessSecretVersionRequest{Name: resource}
	result, err := b.Client.AccessSecretVersion(ctx, req)
	if err != nil {
		e := err.Error()
		return secret.Output{Value: nil, Error: &e}
	}

	value := string(result.Payload.Data)
	return secret.Output{Value: &value, Error: nil}
}
