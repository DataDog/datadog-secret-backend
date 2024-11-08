// Unless explicitly stated otherwise all files in this repository are licensed
// under the BSD 3-Clause License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSecretsOutputWithMissingBackend(t *testing.T) {
	// Ensure that we don't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Code panic in TestGetSecretsOutputWithMissingBackend!")
		}
	}()

	backends := Backends{
		Backends: make(map[string]Backend, 0),
	}

	_, err := backends.GetSecretOutputs([]string{"foo", "bar"})
	require.Error(t, err)
}
