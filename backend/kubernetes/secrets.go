// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package kubernetes allows to fetch secrets from Kubernetes Secrets API
package kubernetes

import (
	"context"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/DataDog/datadog-secret-backend/secret"
)

// SecretsBackendConfig is the configuration for a Kubernetes Secrets backend
type SecretsBackendConfig struct {
	Namespace  string `mapstructure:"namespace"`
	Context    string `mapstructure:"context"`
	Kubeconfig string `mapstructure:"kubeconfig"`
}

// SecretsBackend represents backend for Kubernetes Secrets
type SecretsBackend struct {
	Config SecretsBackendConfig
	Client *kubernetes.Clientset
}

// NewSecretsBackend returns a new Kubernetes Secrets backend
func NewSecretsBackend(bc map[string]interface{}) (*SecretsBackend, error) {
	backendConfig := SecretsBackendConfig{
		Namespace: "default",
	}
	err := mapstructure.Decode(bc, &backendConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to map backend configuration: %s", err)
	}

	var restConfig *rest.Config

	if backendConfig.Kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", backendConfig.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}
	} else {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
		}
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	backend := &SecretsBackend{
		Config: backendConfig,
		Client: client,
	}
	return backend, nil
}

// GetSecretOutput retrieves a secret from Kubernetes Secrets
func (b *SecretsBackend) GetSecretOutput(ctx context.Context, secretString string) secret.Output {
	// parse: secret;key
	// ex: secret;key

	parts := strings.SplitN(secretString, ";", 2)
	secretName, secretKey := parts[0], parts[1]
	namespace := b.Config.Namespace

	k8sSecret, err := b.Client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		es := fmt.Sprintf("failed to get secret '%s' in namespace '%s': %s", secretName, namespace, err.Error())
		return secret.Output{Value: nil, Error: &es}
	}

	data, ok := k8sSecret.Data[secretKey]
	if !ok {
		es := fmt.Sprintf("key '%s' not found in secret '%s' in namespace '%s'", secretKey, secretName, namespace)
		return secret.Output{Value: nil, Error: &es}
	}

	decoded := string(data)
	return secret.Output{Value: &decoded, Error: nil}
}
