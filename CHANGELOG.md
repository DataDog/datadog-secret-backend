# CHANGELOG - datadog-secret-backend

## 1.0.1 / 2025-07-16

* Replacing the dependency on `hashicorp/vault/api/auth/aws` with the forked `DataDog/vault/api/auth/aws` library.

## 1.0.0 / 2025-07-10

* Switched Azure backend to `azsecrets`, removed `go-autorest`.
* Enabled Azure managed identity for secret retrieval.
* Accepting config input via stdin, not separate files.
* Azure secrets can now be flat strings or JSON.
* Removing `secret_id` from AWS Secrets config.
* Removing `parameters_path` from AWS SSM config.
* Removing `secret_path` from Hashicorp config.
* Centralizing secret retrieval in GetSecretOutput.
* Updating Azure Key Vault docs with semicolon syntax.
* Fixing Azure test bug and formatting issues.
* Updated `release.yaml` job to automatically bump `appVersion`.

## 0.2.5 / 2025-06-27

* Bump go version to `1.24.4`

## 0.2.4 / 2025-06-12

* Bump cloudflare/circl to `v1.6.1`
* Bump requests to `v2.32.4`
* Fixing link to AWS docs
* Bump appVersion to 0.2.4

## 0.2.3 / 2025-05-20

* Bump go-git/go-git/v5 to `v5.13.0`
* Bump golang-jwt/jwt/v4 to `v4.5.2`
* Bump golang-jwt/jwt/v5 to `v5.2.2`
* Bump hashicorp/vault to `v1.19.3`
* Bump go-jose/go-jose/v3 to `v3.0.4`
* Bump go-jose/go-jose/v4 to `v4.0.5`
* Limiting workflow permissions to `contents: read` and `pull-requests: write`

## 0.2.2 / 2025-05-19

* Bump hashicorp/vault/api from `v1.15.0` to `v1.16.0`
* Bump golang.org/x/net from `v0.34.0` to `v0.40.0`

## 0.2.1 / 2025-05-07

* Release latest version of the datadog-secret-backend without debug and DWARF symbol.

## 0.2.0 / 2025-04-28

* Build the artifact without debug and DWARF symbol to produce smaller binaries (`-ldflags="-s -w"` is used).

## 0.1.14 / 2025-03-24

* [Fix] Work around Azure issue 39434 & support escaped json strings
* [Documentation] Add permission needed to use aws parameter store
* [CI] Add generate licenses tasks and run them on each PR
* [CI] Running copyrights linter on each PR

## 0.1.13 / 2024-11-19

* Repo ownership transitioned from RapDev to Datadog.
* [Fix] Clean up version flag handling.
* [CI] Adding golangci-lint to the CI and fixing all warnings from the linters.
* [Documentation] Updating contribution guidelines and adding Issue and PR GH templates.

## 0.1.12 / 2024-09-13

* [Added] CI now produces ARM64 artefacts.

## 0.1.11 / 2024-03-20

* [Added] new backend configuration for Akeyless Secrets.

## 0.1.10 / 2022-08-17

* [Added] support for simple string value secrets in AWS Secrets Manager and Azure Key Vault.

## 0.1.7 / 2021-10-20

* [Added] zerolog logger, replacing logrus.
* [Fixed] documentation, adding usage of aws.ssm and aws.secrets backends.
