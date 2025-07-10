// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package aws

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

// secretsManagerMockClient is the struct we'll use to mock the Secrets Manager client
// for unit tests. E2E tests should be written with the real client.
type secretsManagerMockClient struct {
	secrets map[string]string
}

func (c *secretsManagerMockClient) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if params == nil || params.SecretId == nil {
		return nil, secret.ErrKeyNotFound
	}

	if secretValue, exists := c.secrets[*params.SecretId]; exists {
		return &secretsmanager.GetSecretValueOutput{
			Name:         aws.String(*params.SecretId),
			SecretString: aws.String(secretValue),
		}, nil
	}

	return nil, secret.ErrKeyNotFound
}

func TestSecretsManagerBackend(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]string{
			"key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
			"key2": "{\"foo\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams)
	assert.NoError(t, err)
	assert.NotNil(t, secretsManagerSecretsBackend)

	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("key1;user")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "foo", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)

	secretOutput = secretsManagerSecretsBackend.GetSecretOutput("key1;password")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "bar", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)

	secretOutput = secretsManagerSecretsBackend.GetSecretOutput("key1;nonexistent")
	assert.Nil(t, secretOutput.Value)
	assert.NotNil(t, secretOutput.Error)
	assert.Equal(t, secret.ErrKeyNotFound.Error(), *secretOutput.Error)
}

func TestSecretsManagerBackend_ForceString(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]string{
			"key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
			"key2": "{\"foo\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": true,
	}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams)
	assert.NoError(t, err)
	assert.NotNil(t, secretsManagerSecretsBackend)

	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("key1;user")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "{\"user\":\"foo\",\"password\":\"bar\"}", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)
}

func TestSecretsManagerBackend_NotJSON(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]string{
			"key1": "not json",
			"key2": "foobar",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams)
	assert.NoError(t, err)

	// When the secret value is not JSON, it should be returned as-is
	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("key1;anything")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "not json", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)

	secretOutput = secretsManagerSecretsBackend.GetSecretOutput("key2;anything")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "foobar", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)
}

func TestSecretsManagerBackend_InvalidFormat(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]string{
			"key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams)
	assert.NoError(t, err)

	// Test invalid secret format (missing semicolon)
	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("key1")
	assert.Nil(t, secretOutput.Value)
	assert.NotNil(t, secretOutput.Error)
	assert.Equal(t, "invalid secret format, expected 'secret_id;key'", *secretOutput.Error)
}

func TestSecretsManagerBackend_SecretNotFound(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]string{
			"key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams)
	assert.NoError(t, err)

	// Test secret ID that doesn't exist
	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("nonexistent;user")
	assert.Nil(t, secretOutput.Value)
	assert.NotNil(t, secretOutput.Error)
	assert.Equal(t, secret.ErrKeyNotFound.Error(), *secretOutput.Error)
}
