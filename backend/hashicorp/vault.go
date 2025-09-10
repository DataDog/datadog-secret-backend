// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package hashicorp allows to fetch secrets from Hashicorp vault service
package hashicorp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/hashicorp/vault/api/auth/ldap"
	"github.com/hashicorp/vault/api/auth/userpass"
	"github.com/mitchellh/mapstructure"
)

// VaultSessionBackendConfig is the configuration for a Hashicorp vault backend
type VaultSessionBackendConfig struct {
	VaultRoleID              string `mapstructure:"vault_role_id"`
	VaultSecretID            string `mapstructure:"vault_secret_id"`
	VaultUserName            string `mapstructure:"vault_username"`
	VaultPassword            string `mapstructure:"vault_password"`
	VaultLDAPUserName        string `mapstructure:"vault_ldap_username"`
	VaultLDAPPassword        string `mapstructure:"vault_ldap_password"`
	VaultAuthType            string `mapstructure:"vault_auth_type"`
	VaultAWSRole             string `mapstructure:"vault_aws_role"`
	AWSRegion                string `mapstructure:"aws_region"`
	VaultKubernetesRole      string `mapstructure:"vault_kubernetes_role"`
	VaultKubernetesJWT       string `mapstructure:"vault_kubernetes_jwt"`
	VaultKubernetesJWTViaEnv string `mapstructure:"vault_kubernetes_jwt_env"`
	VaultKubernetesJWTPath   string `mapstructure:"vault_kubernetes_jwt_path"`
	VaultKubernetesMountPath string `mapstructure:"vault_kubernetes_mount_path"`
}

// VaultBackendConfig contains the configuration to connect to Hashicorp vault backend
type VaultBackendConfig struct {
	VaultSession VaultSessionBackendConfig `mapstructure:"vault_session"`
	VaultToken   string                    `mapstructure:"vault_token"`
	VaultAddress string                    `mapstructure:"vault_address"`
	VaultTLS     *VaultTLSConfig           `mapstructure:"vault_tls_config"`
}

// VaultTLSConfig contains the TLS and certificate configuration
type VaultTLSConfig struct {
	CACert     string `mapstructure:"ca_cert"`
	CAPath     string `mapstructure:"ca_path"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`
	TLSServer  string `mapstructure:"tls_server"`
	Insecure   bool   `mapstructure:"insecure"`
}

func extractMountFromAuthPath(authPath string) string {
	if strings.HasPrefix(authPath, "auth/") && strings.HasSuffix(authPath, "/login") {
		parts := strings.Split(authPath, "/")
		if len(parts) == 3 {
			return parts[1]
		}
	}
	return "kubernetes" // default
}

// VaultBackend is a backend to fetch secrets from Hashicorp vault
type VaultBackend struct {
	Config VaultBackendConfig
	Client *api.Client
}

// newVaultConfigFromBackendConfig returns a AuthMethod for Hashicorp vault based on the configuration
func newVaultConfigFromBackendConfig(sessionConfig VaultSessionBackendConfig) (api.AuthMethod, error) {
	var auth api.AuthMethod
	var err error
	if sessionConfig.VaultRoleID != "" {
		if sessionConfig.VaultSecretID != "" {
			secretID := &approle.SecretID{FromString: sessionConfig.VaultSecretID}
			auth, err = approle.NewAppRoleAuth(sessionConfig.VaultRoleID, secretID)
			if err != nil {
				return nil, err
			}
		}
	}

	if sessionConfig.VaultUserName != "" {
		if sessionConfig.VaultPassword != "" {
			password := &userpass.Password{FromString: sessionConfig.VaultPassword}
			auth, err = userpass.NewUserpassAuth(sessionConfig.VaultUserName, password)
			if err != nil {
				return nil, err
			}
		}
	}

	if sessionConfig.VaultLDAPUserName != "" {
		if sessionConfig.VaultLDAPPassword != "" {
			password := &ldap.Password{FromString: sessionConfig.VaultLDAPPassword}
			auth, err = ldap.NewLDAPAuth(sessionConfig.VaultLDAPUserName, password)
			if err != nil {
				return nil, err
			}
		}
	}

	if sessionConfig.VaultAuthType == "aws" && sessionConfig.VaultAWSRole != "" {
		opts := []aws.LoginOption{
			aws.WithIAMAuth(),
			aws.WithRole(sessionConfig.VaultAWSRole),
		}

		if sessionConfig.AWSRegion != "" {
			opts = append(opts, aws.WithRegion(sessionConfig.AWSRegion))
		}

		return aws.NewAWSAuth(opts...)
	}

	if sessionConfig.VaultAuthType == "kubernetes" {
		var opts []kubernetes.LoginOption

		// Fallback to legacy env vars if new config fields are missing
		role := sessionConfig.VaultKubernetesRole
		if role == "" {
			role = os.Getenv("DD_SECRETS_VAULT_ROLE")
		}

		// If no role, we cannot proceed
		if role == "" {
			return nil, fmt.Errorf("vault_kubernetes_role not provided and DD_SECRETS_VAULT_ROLE not set")
		}

		// JWT fallback: priority order - explicit JWT, JWT path, JWT env
		if sessionConfig.VaultKubernetesJWT != "" {
			opts = append(opts, kubernetes.WithServiceAccountToken(sessionConfig.VaultKubernetesJWT))
		} else if sessionConfig.VaultKubernetesJWTPath != "" {
			opts = append(opts, kubernetes.WithServiceAccountTokenPath(sessionConfig.VaultKubernetesJWTPath))
		} else if env := sessionConfig.VaultKubernetesJWTViaEnv; env != "" {
			opts = append(opts, kubernetes.WithServiceAccountTokenEnv(env))
		} else if path := os.Getenv("DD_SECRETS_SA_TOKEN_PATH"); path != "" {
			opts = append(opts, kubernetes.WithServiceAccountTokenPath(path))
		} // else: use default path

		// Mount path fallback from DD_SECRETS_VAULT_AUTH_PATH
		mountPath := sessionConfig.VaultKubernetesMountPath
		if mountPath == "" {
			if authPath := os.Getenv("DD_SECRETS_VAULT_AUTH_PATH"); authPath != "" {
				mountPath = extractMountFromAuthPath(authPath)
			}
		}
		if mountPath != "" {
			opts = append(opts, kubernetes.WithMountPath(mountPath))
		}

		// Finally, create the auth method
		fmt.Fprintf(os.Stderr, "K8s auth: role=%q, mountPath=%q\n", role, mountPath)
		fmt.Fprintf(os.Stderr, "Reading service account token from: %q\n", os.Getenv("DD_SECRETS_SA_TOKEN_PATH"))
		return kubernetes.NewKubernetesAuth(role, opts...)
	}

	return auth, err
}

// NewVaultBackend returns a new backend for Hashicorp vault
func NewVaultBackend(bc map[string]interface{}) (*VaultBackend, error) {
	backendConfig := VaultBackendConfig{}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}
	fmt.Fprintf(os.Stderr, "Decoded backendConfig: %+v\n", backendConfig)

	clientConfig := &api.Config{Address: backendConfig.VaultAddress}

	if backendConfig.VaultTLS != nil {
		tlsConfig := &api.TLSConfig{
			CACert:        backendConfig.VaultTLS.CACert,
			CAPath:        backendConfig.VaultTLS.CAPath,
			ClientCert:    backendConfig.VaultTLS.ClientCert,
			ClientKey:     backendConfig.VaultTLS.ClientKey,
			TLSServerName: backendConfig.VaultTLS.TLSServer,
			Insecure:      backendConfig.VaultTLS.Insecure,
		}
		err := clientConfig.ConfigureTLS(tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize vault tls configuration: %s", err)
		}
	}

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %s", err)
	}

	fmt.Fprintf(os.Stderr, "Calling newVaultConfigFromBackendConfig...")
	authMethod, err := newVaultConfigFromBackendConfig(backendConfig.VaultSession)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize vault session: %s", err)
	}
	if authMethod != nil {
		authInfo, err := client.Auth().Login(context.TODO(), authMethod)
		if err != nil {
			return nil, fmt.Errorf("failed to created auth info: %s", err)
		}
		if authInfo == nil {
			return nil, fmt.Errorf("no auth info returned")
		}
	} else if backendConfig.VaultToken != "" {
		client.SetToken(backendConfig.VaultToken)
	} else {
		return nil, fmt.Errorf("no auth method or token provided")
	}

	backend := &VaultBackend{
		Config: backendConfig,
		Client: client,
	}
	return backend, nil
}

// GetSecretOutput returns a the value for a specific secret
func (b *VaultBackend) GetSecretOutput(secretString string) secret.Output {
	segments := strings.SplitN(secretString, ";", 2)
	if len(segments) != 2 {
		es := "invalid secret format, expected 'secret_id;key'"
		return secret.Output{Value: nil, Error: &es}
	}
	secretPath := segments[0]
	secretKey := segments[1]

	// KV version detection:
	// If the mount path is set as /Example/Path, and the secret path is set at /Example/Path/Secret,
	// then we need to query from /Example/Path/data/Secret in kv v2, and /Example/Path/Secret in kv v1.
	isKVv2, mountPrefix := isKVv2Mount(b.Client, secretPath)

	readPath := secretPath
	if isKVv2 {
		readPath = insertDataPath(secretPath, mountPrefix)
	}
	sec, err := b.Client.Logical().Read(readPath)
	if err != nil {
		es := err.Error()
		return secret.Output{Value: nil, Error: &es}
	}

	if sec == nil || sec.Data == nil {
		es := "secret data is nil"
		return secret.Output{Value: nil, Error: &es}
	}

	var dataMap map[string]interface{}
	if isKVv2 {
		if inner, ok := sec.Data["data"].(map[string]interface{}); ok {
			dataMap = inner
		} else {
			es := "secret data is not in expected format for KV v2"
			return secret.Output{Value: nil, Error: &es}
		}
	} else {
		dataMap = sec.Data
	}

	if dataMap == nil {
		es := "There is no actual data in the secret"
		return secret.Output{Value: nil, Error: &es}
	}

	if data, ok := dataMap[secretKey]; ok {
		if strValue, ok := data.(string); ok {
			return secret.Output{Value: &strValue, Error: nil}
		}
		es := "secret value is not a string"
		return secret.Output{Value: nil, Error: &es}
	}

	es := secret.ErrKeyNotFound.Error()
	return secret.Output{Value: nil, Error: &es}
}

func isKVv2Mount(client *api.Client, secretPath string) (bool, string) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, ""
	}

	cleanPath := strings.TrimPrefix(secretPath, "/")
	parts := strings.Split(cleanPath, "/")

	// Try progressively longer prefixes: Datadog/, Datadog/Production/, etc.
	for i := 1; i <= len(parts); i++ {
		prefix := strings.Join(parts[:i], "/") + "/"

		if mountInfo, ok := mounts[prefix]; ok {
			if mountInfo.Type == "kv" {
				version := mountInfo.Options["version"]
				return version == "2", prefix
			}
		}
	}

	// If no mount was found, then assume that it is v1 of the Hashicorp vault secrets engine
	return false, ""
}

func insertDataPath(secretPath, mountPrefix string) string {

	trimmedSecret := strings.TrimPrefix(secretPath, "/")
	trimmedMount := strings.TrimPrefix(mountPrefix, "/")

	if !strings.HasPrefix(trimmedSecret, trimmedMount) {
		// secret path does not match mount prefix, so we are skipping data insertion
		return secretPath
	}

	// remove mount prefix from path
	relative := strings.TrimPrefix(trimmedSecret, trimmedMount)
	relative = strings.TrimPrefix(relative, "/")

	if relative == "" {
		return trimmedMount + "data"
	}
	return trimmedMount + "data/" + relative
}
