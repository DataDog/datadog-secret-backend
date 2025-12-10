// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSecretOutput(t *testing.T) {
	tmpDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpDir, "api_key"), []byte("api-key"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "app_key"), []byte("app-key"), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "empty"), []byte(""), 0644)
	assert.NoError(t, err)

	backend := &SecretsBackend{
		Config: SecretsBackendConfig{
			SecretsPath: tmpDir,
		},
	}

	ctx := context.Background()

	tests := []struct {
		name   string
		secret string
		value  string
		fail   bool
	}{
		{
			name:   "valid secret",
			secret: "api_key",
			value:  "api-key",
			fail:   false,
		},
		{
			name:   "other secret",
			secret: "app_key",
			value:  "app-key",
			fail:   false,
		},
		{
			name:   "secret not found",
			secret: "nonexistent",
			fail:   true,
		},
		{
			name:   "empty secret name",
			secret: "",
			fail:   true,
		},
		{
			name:   "no relative path",
			secret: "../etc/passwd",
			fail:   true,
		},
		{
			name:   "absolute path works",
			secret: filepath.Join(tmpDir, "api_key"),
			value:  "api-key",
			fail:   false,
		},
		{
			name:   "empty secret fails",
			secret: "empty",
			fail:   true,
		},
		{
			name:   "slash in relative name blocked",
			secret: "subdir/secret",
			fail:   true,
		},
		{
			name:   "backslash in relative name blocked (Windows)",
			secret: `subdir\secret`,
			fail:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := backend.GetSecretOutput(ctx, tt.secret)

			if tt.fail {
				assert.Nil(t, output.Value)
				assert.NotNil(t, output.Error)
			} else {
				assert.NotNil(t, output.Value)
				assert.Nil(t, output.Error)
				assert.Equal(t, tt.value, *output.Value)
			}
		})
	}
}

func TestNewSecretsBackend(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name   string
		config map[string]interface{}
		fail   bool
	}{
		{
			name: "valid config with custom path",
			config: map[string]interface{}{
				"secrets_path": tmpDir,
			},
			fail: false,
		},
		{
			name: "nonexistent directory fails",
			config: map[string]interface{}{
				"secrets_path": "/nonexistent/path",
			},
			fail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewSecretsBackend(tt.config)

			if tt.fail {
				assert.Error(t, err)
				assert.Nil(t, backend)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, backend)
			}
		})
	}
}
