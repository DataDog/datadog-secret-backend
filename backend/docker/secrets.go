// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package docker allows to fetch secrets from Docker Secrets (Swarm and Compose) via wrapping the file backend
package docker

import (
	"runtime"

	"github.com/DataDog/datadog-secret-backend/backend/file"
)

// NewDockerSecretsBackend returns a new Docker Secrets backend
func NewDockerSecretsBackend(bc map[string]interface{}) (*file.FileBackend, error) {
	// https://docs.docker.com/engine/swarm/secrets#how-docker-manages-secrets
	// https://docs.docker.com/compose/how-tos/use-secrets/#use-secrets
	if _, exists := bc["secrets_path"]; !exists {
		if runtime.GOOS == "windows" {
			bc["secrets_path"] = `C:\ProgramData\Docker\secrets`
		} else {
			bc["secrets_path"] = "/run/secrets"
		}
	}

	return file.NewFileBackend(bc)
}
