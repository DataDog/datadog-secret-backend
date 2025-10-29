// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package gcp allows to fetch secrets from GCP Secret Manager service
package gcp

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/DataDog/datadog-secret-backend/secret"
)

// SecretManagerBackendConfig is the configuration for GCP Secret Manager backend
type SecretManagerBackendConfig struct{}

// SecretManagerBackend represents backend for GCP Secret Manager
type SecretManagerBackend struct {
	Config SecretManagerBackendConfig
	Client *secretmanager.Client
}

// NewSecretManagerBackend returns a new GCP Secret Manager backend
func NewSecretManagerBackend(bc map[string]interface{}) (*SecretManagerBackend, error) {
	return nil, nil
}

func (b *SecretManagerBackend) GetSecretOutput(secretString string) secret.Output {
	return secret.Output{}
}
