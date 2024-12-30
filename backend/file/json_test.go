// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/stretchr/testify/assert"
)

func TestJSONBackend(t *testing.T) {
	tmpDir := t.TempDir()
	secretsFilepath := filepath.Join(tmpDir, "secrets.json")
	tempFile, err := os.Create(secretsFilepath)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	secretsData := `{"key1": "value1", "key2": "value2"}`
	if _, err := tempFile.Write([]byte(secretsData)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	jsonSecretsBackendParams := map[string]interface{}{
		"backend_type": "json",
		"file_path":    secretsFilepath,
	}
	jsonSecretsBackend, err := NewJSONBackend("json-backend", jsonSecretsBackendParams)
	assert.NoError(t, err)

	assert.Equal(t, "json-backend", jsonSecretsBackend.BackendID)
	assert.Equal(t, "json", jsonSecretsBackend.Config.BackendType)
	assert.Equal(t, secretsFilepath, jsonSecretsBackend.Config.FilePath)

	secretOutput := jsonSecretsBackend.GetSecretOutput("key1")
	assert.Equal(t, "value1", *secretOutput.Value)
	assert.Nil(t, secretOutput.Error)

	secretOutput = jsonSecretsBackend.GetSecretOutput("key_noexist")
	assert.Nil(t, secretOutput.Value)
	assert.Equal(t, secret.ErrKeyNotFound.Error(), *secretOutput.Error)
}
