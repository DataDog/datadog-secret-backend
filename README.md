# datadog-secret-backend

[![.github/workflows/release.yaml](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml/badge.svg)](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml)

> **datadog-secret-backend** is an implementation of the [Datadog Agent Secrets Management](https://docs.datadoghq.com/agent/guide/secrets-management/?tab=linux) executable supporting multiple backend secret providers.

**IMPORTANT NOTE**: We have made BREAKING changes to this repo in the main branch. 

1. We are only supported one backend type being configured (this is why specifying backendID is no longer needed)
2. The backend config is being written to stdin by the Datadog Agent, so any yaml file (except for the `datadog.yaml` file used to configure your Agent) won't be considered.

To create a standalone executable from this repository, please switch to the `v0` branch, and follow the README instructions in that branch. Read the main branch's README if you wish for Datadog to handle the pulling of secrets automatically.

## Supported Backends

| Backend | Provider | Description |
| :-- | :-- | :-- |
| [aws.secrets](docs/aws/secrets.md) | [aws](docs/aws/README.md) | Datadog secrets in AWS Secrets Manager |
| [aws.ssm](docs/aws/ssm.md) | [aws](docs/aws/README.md) | Datadog secrets in AWS Systems Manager Parameter Store |
| [azure.keyvault](docs/azure/keyvault.md) | [azure](docs/azure/README.md) | Datadog secrets in Azure Key Vault |
| [hashicorp.vault](docs/hashicorp/vault.md) | [hashicorp](docs/hashicorp/README.md) | Datadog secrets in Hashicorp Vault |
| [file.json](docs/file/json.md) | [file](docs/file/README.md) | Datadog secrets in local JSON files|
| [file.yaml](docs/file/yaml.md) | [file](docs/file/README.md) | Datadog secrets in local YAML files|

## Installation

This executable is now shipped along with the Datadog Agent in agent versions >=7.69. All you need to do to use this feature with one of the supported backends is [provide a configuration](https://github.com/DataDog/datadog-secret-backend/blob/main/datadog-secret-backend.yaml.example) for the secrets executable.

## Usage

Reference each supported backend type's documentation on specific usage examples and configuration options.

## License

[BSD-3-Clause License](LICENSE)
