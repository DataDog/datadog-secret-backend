package gcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockSecretManagerServer creates a test HTTP server that mocks GCP Secret Manager
func mockSecretManagerServer(secrets map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, value := range secrets {
			if strings.Contains(r.URL.Path, fmt.Sprintf("secrets/%s/versions", name)) {
				response := accessSecretVersionResponse{
					Payload: struct {
						Data       string `json:"data"`
						DataCRC32C string `json:"dataCrc32c"`
					}{
						Data: base64.StdEncoding.EncodeToString([]byte(value)),
					},
				}
				json.NewEncoder(w).Encode(response)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}))
}

func TestNewSecretManagerBackendInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name:   "empty config",
			config: map[string]interface{}{},
		},
		{
			name: "missing project_id",
			config: map[string]interface{}{
				"gcp_session": map[string]interface{}{},
			},
		},
		{
			name: "empty project_id",
			config: map[string]interface{}{
				"gcp_session": map[string]interface{}{
					"project_id": "",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend, err := NewSecretManagerBackend(test.config)
			assert.Error(t, err)
			assert.Nil(t, backend)
		})
	}
}

func TestSecretManagerBackend(t *testing.T) {
	mockServer := mockSecretManagerServer(map[string]string{
		"secretX": "valueX",
		"secretY": "valueY",
	})
	defer mockServer.Close()

	backend := &SecretManagerBackend{
		Config: SecretManagerBackendConfig{
			Session: struct {
				ProjectID string `mapstructure:"project_id"`
			}{ProjectID: "test-project"},
		},
		Client: mockServer.Client(),
	}

	// overrides serviceEndpoint to point to the mock server
	serviceEndpoint = mockServer.URL

	tests := []struct {
		name   string
		secret string
		value  string
		fail   bool
	}{
		{
			name:   "basic secret fetch",
			secret: "secretX",
			value:  "valueX",
			fail:   false,
		},
		{
			name:   "secret with explicit version",
			secret: "secretY@latest",
			value:  "valueY",
			fail:   false,
		},
		{
			name:   "secret not found",
			secret: "nonexistent",
			fail:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := backend.GetSecretOutput(test.secret)
			if test.fail {
				assert.Nil(t, output.Value)
				assert.NotNil(t, output.Error)
			} else {
				assert.NotNil(t, output.Value)
				assert.Equal(t, test.value, *output.Value)
				assert.Nil(t, output.Error)
			}
		})
	}
}

func TestSecretManagerBackendVersionParsing(t *testing.T) {
	mockServer := mockSecretManagerServer(map[string]string{
		"my-secret": "secret-value",
	})
	defer mockServer.Close()

	backend := &SecretManagerBackend{
		Config: SecretManagerBackendConfig{
			Session: struct {
				ProjectID string `mapstructure:"project_id"`
			}{ProjectID: "test-project"},
		},
		Client: mockServer.Client(),
	}

	// overrides serviceEndpoint to point to the mock server
	serviceEndpoint = mockServer.URL

	tests := []struct {
		name   string
		secret string
		value  string
	}{
		{
			name:   "default version",
			secret: "my-secret",
			value:  "secret-value",
		},
		{
			name:   "latest version",
			secret: "my-secret@latest",
			value:  "secret-value",
		},
		{
			name:   "explicit version number",
			secret: "my-secret@1",
			value:  "secret-value",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := backend.GetSecretOutput(test.secret)
			assert.NotNil(t, output.Value)
			assert.Equal(t, test.value, *output.Value)
		})
	}
}

func TestSecretManagerBackend_ErrorHandling(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "permission denied"}`))
	}))
	defer mockServer.Close()

	backend := &SecretManagerBackend{
		Config: SecretManagerBackendConfig{
			Session: struct {
				ProjectID string `mapstructure:"project_id"`
			}{ProjectID: "test-project"},
		},
		Client: mockServer.Client(),
	}

	// overrides serviceEndpoint to point to the mock server
	serviceEndpoint = mockServer.URL

	output := backend.GetSecretOutput("any-secret")
	assert.Nil(t, output.Value)
	assert.NotNil(t, output.Error)
	assert.Contains(t, *output.Error, "403")
}
