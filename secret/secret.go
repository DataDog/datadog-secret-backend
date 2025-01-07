// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.
// Copyright (c) 2021, RapDev.IO

// Package secret contains the structure to receive and return secrets to the Datadog Agent
package secret

// Input represents a secret to be resolved
type Input struct {
	Secrets []string `json:"secrets"`
	Version string   `json:"version"`
}

// Output represents a resolved secret
type Output struct {
	Value *string `json:"value"`
	Error *string `json:"error"`
}

type Keys struct {
	Keys  []string `json:"keys"`
	Error *string  `json:"error"`
}
