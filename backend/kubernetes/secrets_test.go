// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

package kubernetes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetSecretOutput(t *testing.T) {

	backend := &SecretsBackend{
		Client: fake.NewSimpleClientset(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-secrets",
					Namespace: "secrets-x",
				},
				Data: map[string][]byte{
					"password": []byte("password"),
					"username": []byte("admin"),
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-secrets",
					Namespace: "secrets-y",
				},
				Data: map[string][]byte{
					"password": []byte("db-password"),
					"host":     []byte("localhost"),
				},
			},
		),
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
			errorContains: "failed to get secret",
		},
		{
			name:          "namespace not found",
			secretString:  "nonexistent-ns/my-secrets;password",
			expectError:   true,
			errorContains: "failed to get secret",
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
	fakeClient := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "empty-secret",
				Namespace: "test-ns",
			},
			Data: nil,
		},
	)

	backend := &SecretsBackend{
		Client: fakeClient,
	}

	ctx := context.Background()
	output := backend.GetSecretOutput(ctx, "test-ns/empty-secret;password")

	assert.NotNil(t, output.Error)
	assert.Nil(t, output.Value)
	assert.Contains(t, *output.Error, "has no data")
}

func TestGetSecretOutputEdgeCases(t *testing.T) {
	backend := &SecretsBackend{
		Client: fake.NewSimpleClientset(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-secrets",
					Namespace: "secrets-x",
				},
				Data: map[string][]byte{
					"password": []byte("password"),
				},
			},
		),
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
			errorContains: "failed to get secret 'sub/path'",
		},
		{
			name:          "double slash",
			secretString:  "secrets-x//my-secrets;password",
			expectError:   true,
			errorContains: "failed to get secret",
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
