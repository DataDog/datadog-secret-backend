// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package azure allows to fetch secrets from Azure keyvault service
package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

// keyvaultClient is an interface that defines the methods we use from the ssm client
// As the AWS SDK doesn't provide a real mock, we'll have to make our own that
// matches this interface
type keyvaultClient interface {
	GetSecret(ctx context.Context, secretID string, secretVersion string, opt *azsecrets.GetSecretOptions) (result azsecrets.GetSecretResponse, err error)
}

// getKeyvaultClient is a variable that holds the function to create a new keyvaultClient
// it will be overwritten in tests
var getKeyvaultClient = func(keyVaultURL string) keyvaultClient {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Errorf("getting default credentials: %s", err)
	}
	client, err := azsecrets.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	return client
}

// KeyVaultBackendConfig contains the configuration to connect for Azure backend
type KeyVaultBackendConfig struct {
	Session     *SessionBackendConfig `mapstructure:"azure_session"`
	BackendType string                `mapstructure:"backend_type"`
	ForceString bool                  `mapstructure:"force_string"`
	KeyVaultURL string                `mapstructure:"keyvaulturl"`
	SecretID    string                `mapstructure:"secret_id"`
}

// KeyVaultBackend is a backend to fetch secrets from Azure
type KeyVaultBackend struct {
	BackendID string
	Config    KeyVaultBackendConfig
	Secret    map[string]string
}

// NewKeyVaultBackend returns a new backend for Azure
func NewKeyVaultBackend(backendID string, bc map[string]interface{}) (*KeyVaultBackend, error) {
	backendConfig := KeyVaultBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		log.WithError(err).Error("failed to map backend configuration")
		return nil, err
	}

	client := getKeyvaultClient(backendConfig.KeyVaultURL)

	version := ""
	out, err := client.GetSecret(context.Background(), backendConfig.SecretID, version, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"backend_id":   backendID,
			"backend_type": backendConfig.BackendType,
			"secret_id":    backendConfig.SecretID,
			"keyvaulturl":  backendConfig.KeyVaultURL,
		}).WithError(err).Error("failed to retrieve secret value")
		return nil, err
	}

	secretValue := make(map[string]string, 0)
	if backendConfig.ForceString {
		secretValue["_"] = *out.Value
	} else {
		err := json.Unmarshal([]byte(*out.Value), &secretValue)
		if err != nil {
			// See https://github.com/Azure/azure-sdk-for-net/issues/39434, Azure KeyVault can return an escaped string value
			// that is not parsable as is. We need to unquote it first.
			unquoted, err := strconv.Unquote(fmt.Sprintf(`"%s"`, *out.Value))
			if err != nil {
				// assume: not json, store as single key -> string value
				secretValue["_"] = *out.Value
			} else {
				err := json.Unmarshal([]byte(unquoted), &secretValue)
				if err != nil {
					// assume: not json, store as single key -> string value
					secretValue["_"] = unquoted
				}
			}
		}
	}

	backend := &KeyVaultBackend{
		BackendID: backendID,
		Config:    backendConfig,
		Secret:    secretValue,
	}
	return backend, nil
}

// GetSecretOutput returns a the value for a specific secret
func (b *KeyVaultBackend) GetSecretOutput(secretKey string) secret.Output {
	if val, ok := b.Secret[secretKey]; ok {
		return secret.Output{Value: &val, Error: nil}
	}
	es := secret.ErrKeyNotFound.Error()

	log.WithFields(log.Fields{
		"backend_id":   b.BackendID,
		"backend_type": b.Config.BackendType,
		"secret_id":    b.Config.SecretID,
		"keyvaulturl":  b.Config.KeyVaultURL,
		"secret_key":   secretKey,
	}).Error("backend does not provide secret key")
	return secret.Output{Value: nil, Error: &es}
}
