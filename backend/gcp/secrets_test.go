package gcp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSecretManagerBackend(t *testing.T) {
	config := map[string]interface{}{
		"gcp_session": map[string]interface{}{
			"project_id": "test-project",
		},
	}

	backend, err := NewSecretManagerBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
	assert.Equal(t, "test-project", backend.Config.Session.ProjectID)
}

func TestGetSecretOutputLocal(t *testing.T) {
	config := map[string]interface{}{
		"gcp_session": map[string]interface{}{
			"project_id": "datadog-sandbox",
		},
	}

	backend, err := NewSecretManagerBackend(config)
	assert.NoError(t, err)
	assert.NotNil(t, backend)

	secretOutput := backend.GetSecretOutput("test-secret-for-gcp-backend")
	fmt.Println(secretOutput)
	if secretOutput.Error != nil {
		fmt.Printf("Error fetching secret: %s\n", *secretOutput.Error)
	} else {
		fmt.Printf("Fetched secret value: %s\n", *secretOutput.Value)
	}
	assert.NotNil(t, secretOutput)
}
