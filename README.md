# datadog-secret-backend

> [!IMPORTANT]
> **This repository has been archived and is now read-only.**
>
> The `datadog-secret-backend` project has been migrated into the [Datadog Agent monorepo](https://github.com/DataDog/datadog-agent) as `secret-generic-connector`.
> See the [Datadog Agent Secrets Management documentation](https://docs.datadoghq.com/agent/guide/secrets-management/).
>
> - **Agent 7.70+**: The secret backend binary was first bundled inside the Agent. Separate installation of `datadog-secret-backend` is no longer needed -- configure using `secret_backend_type` and `secret_backend_config` in your `datadog.yaml`.
> - **Agent 7.77.0+**: The source code now lives in the Agent repo and includes FIPS compliance support.
>
> **For existing users:** Existing installations of this standalone binary will continue to work with newer Agent. But we strongly recommend upgrading to Agent 7.77.0+ and migrating to `secret_backend_type` configuration to benefit from the latest improvements (new features and CVE fixes from the cloud providers SDK used by this project).
>
> **For contributors and developers:**
> - Source code: [`cmd/secret-generic-connector`](https://github.com/DataDog/datadog-agent/tree/main/cmd/secret-generic-connector)
> - Issues: [Datadog Agent Issues](https://github.com/DataDog/datadog-agent/issues)

---

[![.github/workflows/release.yaml](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml/badge.svg)](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml)

> **datadog-secret-backend** is an implementation of the [Datadog Agent Secrets Management](https://docs.datadoghq.com/agent/guide/secrets-management/?tab=linux) executable supporting multiple backend secret providers.

This branch contains `v1` of `datadog-secret-backend`, which introduced a simplified configuration process and tighter integration with the Datadog Agent. It is not compatible with `v0` configuration files.
The `v1` version provided the following key improvements:
1. The `datadog-secret-backend` is shipped within the Datadog Agent starting with version 7.69.
2. The backend is configured directly within the configuration file of the Datadog Agent rather than a dedicated external file.
3. The type of backend is configured directly from the configuration file of the Datadog Agent. There is no need to prefix your secret with the `backendID`.

More information can be found in the [Datadog Secrets Management documentation](https://docs.datadoghq.com/agent/configuration/secrets-management).

## Supported Backends

For the full list of supported backends, configuration options, and usage examples, see the [Datadog Secrets Management documentation](https://docs.datadoghq.com/agent/configuration/secrets-management).

## License

[BSD-3-Clause License](LICENSE)
