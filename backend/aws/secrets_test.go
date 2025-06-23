// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

// secretsManagerMockClient is the struct we'll use to mock the Secrets Manager client
// for unit tests. E2E tests should be written with the real client.
type secretsManagerMockClient struct {
	secrets map[string]interface{}
}

func (c *secretsManagerMockClient) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if params == nil || params.SecretId == nil {
		return nil, nil
	}

	for key, value := range c.secrets {
		segments := strings.SplitN(key, ";", 2)
		if len(segments) == 2 && segments[1] == *params.SecretId {
			return &secretsmanager.GetSecretValueOutput{
				Name:         aws.String(segments[1]),
				SecretString: aws.String(value.(string)),
			}, nil
		}
	}
	return nil, secret.ErrKeyNotFound
}

func TestSecretsManagerBackend(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]interface{}{
			"something1;key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
			"something2;key2": "{\"foo\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerBackendSecrets := []string{"key1;user", "key1;password"}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams, secretsManagerBackendSecrets)
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
		secrets: map[string]interface{}{
			"something1;key1": "{\"user\":\"foo\",\"password\":\"bar\"}",
			"something2;key2": "{\"foo\":\"bar\"}",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": true,
	}
	secretsManagerBackendSecrets := []string{"key1;user", "key1;password"}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams, secretsManagerBackendSecrets)
	assert.NoError(t, err)
	assert.NotNil(t, secretsManagerSecretsBackend)

	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("key1;user")
	assert.NotNil(t, secretOutput.Value)
	assert.Equal(t, "{\"user\":\"foo\",\"password\":\"bar\"}", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)
}

func TestSecretsManagerBackend_NotJSON(t *testing.T) {
	mockClient := &secretsManagerMockClient{
		secrets: map[string]interface{}{
			"something1;key1": "not json",
			"something2;key2": "foobar",
		},
	}
	getSecretsManagerClient = func(_ aws.Config) secretsManagerClient {
		return mockClient
	}

	secretsManagerBackendParams := map[string]interface{}{
		"backend_type": "aws.secrets",
		"force_string": false,
	}
	secretsManagerBackendSecrets := []string{"key1;value1", "key2;value2"}
	secretsManagerSecretsBackend, err := NewSecretsManagerBackend(secretsManagerBackendParams, secretsManagerBackendSecrets)
	assert.NoError(t, err)

	// Top-level keys are not fetchable
	secretOutput := secretsManagerSecretsBackend.GetSecretOutput("something1;key1")
	assert.Nil(t, secretOutput.Value)
	assert.Equal(t, secret.ErrKeyNotFound.Error(), *secretOutput.Error)

	secretOutput = secretsManagerSecretsBackend.GetSecretOutput("something2;key2")
	assert.Nil(t, secretOutput.Value)
	assert.Equal(t, secret.ErrKeyNotFound.Error(), *secretOutput.Error)
}
