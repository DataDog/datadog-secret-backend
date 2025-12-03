// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// createMockK8sServer creates a test HTTP server that mimics K8s API
func createMockK8sServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(k8sErrorResponse{
				Message: "Unauthorized",
				Reason:  "Unauthorized",
				Code:    401,
			})
			return
		}

		switch r.URL.Path {
		case "/api/v1/namespaces/secrets-x/secrets/my-secrets":
			json.NewEncoder(w).Encode(k8sSecretResponse{
				Data: map[string]string{
					"password": base64.StdEncoding.EncodeToString([]byte("password")),
					"username": base64.StdEncoding.EncodeToString([]byte("admin")),
					"api_key":  base64.StdEncoding.EncodeToString([]byte("key-123")),
				},
			})
		case "/api/v1/namespaces/secrets-y/secrets/db-secrets":
			json.NewEncoder(w).Encode(k8sSecretResponse{
				Data: map[string]string{
					"password": base64.StdEncoding.EncodeToString([]byte("db-password")),
					"host":     base64.StdEncoding.EncodeToString([]byte("localhost")),
				},
			})
		case "/api/v1/namespaces/test-ns/secrets/empty-secret":
			json.NewEncoder(w).Encode(k8sSecretResponse{
				Data: nil,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(k8sErrorResponse{
				Message: `secrets "unknown" not found`,
				Reason:  "NotFound",
				Code:    404,
			})
		}
	}))
}

func TestGetSecretOutput(t *testing.T) {
	server := createMockK8sServer()
	defer server.Close()

	backend := &SecretsBackend{
		HTTPClient: server.Client(),
		K8sConfig: k8sConfig{
			Host:        server.URL,
			BearerToken: "test-token",
		},
	}

	tests := []struct {
		name          string
		secretString  string
		expectError   bool
		expectedValue string
		errorContains string
	}{
		{
			name:          "valid secret",
			secretString:  "secrets-x/my-secrets;password",
			expectError:   false,
			expectedValue: "password",
		},
		{
			name:          "valid secret different key",
			secretString:  "secrets-x/my-secrets;username",
			expectError:   false,
			expectedValue: "admin",
		},
		{
			name:          "different namespace",
			secretString:  "secrets-y/db-secrets;password",
			expectError:   false,
			expectedValue: "db-password",
		},
		{
			name:          "different namespace different key",
			secretString:  "secrets-y/db-secrets;host",
			expectError:   false,
			expectedValue: "localhost",
		},
		{
			name:          "invalid format - missing key",
			secretString:  "secrets-x/my-secrets",
			expectError:   true,
			errorContains: "invalid secret format",
		},
		{
			name:          "invalid format - missing namespace",
			secretString:  "my-secrets;password",
			expectError:   true,
			errorContains: "invalid secret format",
		},
		{
			name:          "secret not found",
			secretString:  "secrets-x/nonexistent;password",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "namespace not found",
			secretString:  "nonexistent-ns/my-secrets;password",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "key not found in secret",
			secretString:  "secrets-x/my-secrets;nonexistent",
			expectError:   true,
			errorContains: "key 'nonexistent' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			output := backend.GetSecretOutput(ctx, tt.secretString)

			if tt.expectError {
				assert.NotNil(t, output.Error)
				assert.Nil(t, output.Value)
				if tt.errorContains != "" {
					assert.Contains(t, *output.Error, tt.errorContains)
				}
			} else {
				assert.Nil(t, output.Error)
				assert.NotNil(t, output.Value)
				assert.Equal(t, tt.expectedValue, *output.Value)
			}
		})
	}
}

func TestGetSecretOutputEmptyData(t *testing.T) {
	server := createMockK8sServer()
	defer server.Close()

	backend := &SecretsBackend{
		HTTPClient: server.Client(),
		K8sConfig: k8sConfig{
			Host:        server.URL,
			BearerToken: "test-token",
		},
	}

	ctx := context.Background()
	output := backend.GetSecretOutput(ctx, "test-ns/empty-secret;password")

	assert.NotNil(t, output.Error)
	assert.Nil(t, output.Value)
	assert.Contains(t, *output.Error, "has no data")
}

func TestGetSecretOutputEdgeCases(t *testing.T) {
	server := createMockK8sServer()
	defer server.Close()

	backend := &SecretsBackend{
		HTTPClient: server.Client(),
		K8sConfig: k8sConfig{
			Host:        server.URL,
			BearerToken: "test-token",
		},
	}

	tests := []struct {
		name          string
		secretString  string
		expectError   bool
		errorContains string
	}{
		{
			name:          "multiple semicolons",
			secretString:  "secrets-x/my-secrets;password;extra",
			expectError:   true,
			errorContains: "key 'password;extra' not found",
		},
		{
			name:          "multiple slashes",
			secretString:  "secrets-x/sub/path;password",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "double slash",
			secretString:  "secrets-x//my-secrets;password",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "empty secret name after slash",
			secretString:  "secrets-x/;password",
			expectError:   true,
			errorContains: "cannot be empty",
		},
		{
			name:          "missing namespace before slash",
			secretString:  "/my-secrets;password",
			expectError:   true,
			errorContains: "cannot be empty",
		},
		{
			name:          "missing everything before semicolon",
			secretString:  ";password",
			expectError:   true,
			errorContains: "invalid secret format",
		},
		{
			name:          "empty key after semicolon",
			secretString:  "secrets-x/my-secrets;",
			expectError:   true,
			errorContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			output := backend.GetSecretOutput(ctx, tt.secretString)

			assert.NotNil(t, output.Error)
			assert.Nil(t, output.Value)
			if tt.errorContains != "" {
				assert.Contains(t, *output.Error, tt.errorContains)
			}
		})
	}
}
