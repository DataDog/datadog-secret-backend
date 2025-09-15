// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package hashicorp allows to fetch secrets from Hashicorp vault service
package hashicorp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-secret-backend/secret"
	"github.com/mitchellh/mapstructure"
	"github.com/qri-io/jsonpointer"
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
	ForceKVv2    bool                      `mapstructure:"force_kv_v2"`
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

// VaultBackend is a backend to fetch secrets from Hashicorp vault
type VaultBackend struct {
	Config     VaultBackendConfig
	httpClient *http.Client
	token      string
	baseURL    string
	mutex      sync.RWMutex
}

// VaultAuthResponse represents the response from Vault auth
type VaultAuthResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
		Accessor    string `json:"accessor"`
	} `json:"auth"`
}

// VaultSecretResponse represents a secret response from Vault
type VaultSecretResponse struct {
	Data          map[string]interface{} `json:"data"`
	LeaseDuration int                    `json:"lease_duration"`
	LeaseID       string                 `json:"lease_id"`
	Renewable     bool                   `json:"renewable"`
	RequestID     string                 `json:"request_id"`
	Warnings      []string               `json:"warnings"`
}

// safeExtractMountFromAuthPath safely extracts mount path from auth path
func safeExtractMountFromAuthPath(authPath string) string {
	fmt.Fprintf(os.Stderr, "DEBUG: Extracting mount path from %q\n", authPath)

	if !strings.HasPrefix(authPath, "auth/") || !strings.HasSuffix(authPath, "/login") {
		return "kubernetes"
	}

	// Remove "auth/" prefix and "/login" suffix safely
	if len(authPath) <= 11 { // "auth/" + "/login" = 11 chars minimum
		return "kubernetes"
	}

	result := authPath[5 : len(authPath)-6] // Remove "auth/" and "/login"
	fmt.Fprintf(os.Stderr, "DEBUG: Extracted mount path: %q\n", result)
	return result
}

// NewVaultBackend returns a new backend for Hashicorp vault
func NewVaultBackend(bc map[string]interface{}) (*VaultBackend, error) {
	var config VaultBackendConfig
	if err := mapstructure.Decode(bc, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	// Create HTTP client with reasonable timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	backend := &VaultBackend{
		Config:     config,
		httpClient: client,
		baseURL:    strings.TrimRight(config.VaultAddress, "/"),
	}

	// Authenticate and get token
	if err := backend.authenticate(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return backend, nil
}

func (b *VaultBackend) authenticate() error {
	if b.Config.VaultToken != "" {
		b.token = b.Config.VaultToken
		return nil
	}

	if b.Config.VaultSession.VaultAuthType == "kubernetes" {
		return b.authenticateKubernetes()
	}

	return fmt.Errorf("no supported authentication method configured")
}

func (b *VaultBackend) authenticateKubernetes() error {
	// Get role
	role := b.Config.VaultSession.VaultKubernetesRole
	if role == "" {
		role = os.Getenv("DD_SECRETS_VAULT_ROLE")
	}
	if role == "" {
		return fmt.Errorf("kubernetes role not specified")
	}

	// Get JWT token
	var jwtToken string
	if b.Config.VaultSession.VaultKubernetesJWT != "" {
		jwtToken = b.Config.VaultSession.VaultKubernetesJWT
	} else {
		// Read from file
		tokenPath := b.Config.VaultSession.VaultKubernetesJWTPath
		if tokenPath == "" {
			tokenPath = os.Getenv("DD_SECRETS_SA_TOKEN_PATH")
		}
		if tokenPath == "" {
			tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		}

		tokenBytes, err := os.ReadFile(tokenPath)
		if err != nil {
			return fmt.Errorf("failed to read JWT token from %s: %w", tokenPath, err)
		}
		jwtToken = strings.TrimSpace(string(tokenBytes))
	}

	// Get mount path
	mountPath := b.Config.VaultSession.VaultKubernetesMountPath
	if mountPath == "" {
		if authPath := os.Getenv("DD_SECRETS_VAULT_AUTH_PATH"); authPath != "" {
			mountPath = safeExtractMountFromAuthPath(authPath)
		}
	}
	if mountPath == "" {
		mountPath = "kubernetes"
	}

	fmt.Fprintf(os.Stderr, "Authenticating with role=%q, mountPath=%q\n", role, mountPath)

	// Prepare auth request
	authData := map[string]interface{}{
		"jwt":  jwtToken,
		"role": role,
	}

	authURL := fmt.Sprintf("%s/v1/auth/%s/login", b.baseURL, mountPath)
	return b.performAuth(authURL, authData)
}

func (b *VaultBackend) performAuth(authURL string, authData map[string]interface{}) error {
	jsonData, err := json.Marshal(authData)
	if err != nil {
		return fmt.Errorf("failed to marshal auth data: %w", err)
	}

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp VaultAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	if authResp.Auth.ClientToken == "" {
		return fmt.Errorf("no token in auth response")
	}

	b.token = authResp.Auth.ClientToken
	fmt.Fprintf(os.Stderr, "Authentication successful\n")
	return nil
}

func (b *VaultBackend) parseSecretString(secretString string) (string, interface{}, error) {
	if strings.HasPrefix(secretString, "vault://") {
		pathWithKey := strings.TrimPrefix(secretString, "vault://")
		parts := strings.SplitN(pathWithKey, "#", 2)
		if len(parts) != 2 {
			return "", nil, fmt.Errorf("invalid vault:// format")
		}

		pointer, err := jsonpointer.Parse(parts[1])
		if err != nil {
			return "", nil, fmt.Errorf("invalid JSON pointer: %w", err)
		}

		return parts[0], pointer, nil
	}

	parts := strings.SplitN(secretString, ";", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid format, expected 'path;key' or 'vault://path#/json/pointer'")
	}

	return parts[0], parts[1], nil
}

func (b *VaultBackend) GetSecretOutput(secretString string) secret.Output {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	secretPath, keyOrPointer, err := b.parseSecretString(secretString)
	if err != nil {
		errMsg := err.Error()
		return secret.Output{Value: nil, Error: &errMsg}
	}

	// Determine read path
	readPath := secretPath
	isKVv2 := b.Config.ForceKVv2
	if isKVv2 {
		readPath = b.buildKVv2Path(secretPath)
	}

	// Read secret
	secretData, err := b.readSecret(readPath)
	if err != nil {
		errMsg := err.Error()
		return secret.Output{Value: nil, Error: &errMsg}
	}

	// Handle JSON pointer format
	if pointer, ok := keyOrPointer.(jsonpointer.Pointer); ok {
		return b.handleJSONPointer(secretData, pointer, secretPath)
	}

	// Handle simple key format
	return b.handleSimpleKey(secretData, keyOrPointer.(string), isKVv2)
}

func (b *VaultBackend) readSecret(path string) (*VaultSecretResponse, error) {
	url := fmt.Sprintf("%s/v1/%s", b.baseURL, strings.TrimPrefix(path, "/"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", b.token)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var secretResp VaultSecretResponse
	if err := json.Unmarshal(body, &secretResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &secretResp, nil
}

func (b *VaultBackend) buildKVv2Path(secretPath string) string {
	cleanPath := strings.TrimPrefix(secretPath, "/")
	parts := strings.Split(cleanPath, "/")

	if len(parts) >= 2 {
		return parts[0] + "/data/" + strings.Join(parts[1:], "/")
	}

	return secretPath + "/data"
}

func (b *VaultBackend) handleJSONPointer(secretData *VaultSecretResponse, pointer jsonpointer.Pointer, vaultPath string) secret.Output {
	head := pointer.Head()
	if head == nil {
		errMsg := "invalid JSON pointer"
		return secret.Output{Value: nil, Error: &errMsg}
	}

	var value interface{}
	var err error

	switch *head {
	case "data":
		value, err = pointer.Tail().Eval(secretData.Data)
		if err != nil {
			errMsg := fmt.Sprintf("JSON pointer evaluation failed: %v", err)
			return secret.Output{Value: nil, Error: &errMsg}
		}
	case "lease_duration":
		value = secretData.LeaseDuration
	case "lease_id":
		value = secretData.LeaseID
	case "renewable":
		value = secretData.Renewable
	case "request_id":
		value = secretData.RequestID
	case "warnings":
		value = secretData.Warnings
	default:
		errMsg := fmt.Sprintf("unsupported pointer key: %s", *head)
		return secret.Output{Value: nil, Error: &errMsg}
	}

	if value == nil {
		errMsg := fmt.Sprintf("no value found for pointer %s", pointer)
		return secret.Output{Value: nil, Error: &errMsg}
	}

	valueStr := fmt.Sprintf("%v", value)
	return secret.Output{Value: &valueStr, Error: nil}
}

func (b *VaultBackend) handleSimpleKey(secretData *VaultSecretResponse, key string, isKVv2 bool) secret.Output {
	var dataMap map[string]interface{}

	if isKVv2 {
		if inner, ok := secretData.Data["data"].(map[string]interface{}); ok {
			dataMap = inner
		} else {
			errMsg := "KV v2 data not in expected format"
			return secret.Output{Value: nil, Error: &errMsg}
		}
	} else {
		dataMap = secretData.Data
	}

	if dataMap == nil {
		errMsg := "no data in secret"
		return secret.Output{Value: nil, Error: &errMsg}
	}

	if value, ok := dataMap[key]; ok {
		if strValue, ok := value.(string); ok {
			return secret.Output{Value: &strValue, Error: nil}
		}
		errMsg := "secret value is not a string"
		return secret.Output{Value: nil, Error: &errMsg}
	}

	errMsg := fmt.Sprintf("key %q not found", key)
	return secret.Output{Value: nil, Error: &errMsg}
}
