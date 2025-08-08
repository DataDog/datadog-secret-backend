# datadog-secret-backend

[![.github/workflows/release.yaml](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml/badge.svg)](https://github.com/DataDog/datadog-secret-backend/actions/workflows/release.yaml)

> **datadog-secret-backend** is an implementation of the [Datadog Agent Secrets Management](https://docs.datadoghq.com/agent/guide/secrets-management/?tab=linux) executable supporting multiple backend secret providers.

**IMPORTANT NOTE**: If you're using a non-Windows Agent version 7.69 or newer, setup is significantly simplified because the datadog-secret-backend binary is now bundled inside the Agent itself. In that case, you don’t need to install or manage the binary separately--please use the [secret_backend_type](https://github.com/DataDog/datadog-agent/blob/main/pkg/config/config_template.yaml#L867) and [secret_backend_config](https://github.com/DataDog/datadog-agent/blob/main/pkg/config/config_template.yaml#L880) config options in your datadog.yaml file instead.

## Quick Start (Agent Version < 7.69 or using Windows)

1. For agents before < `7.69.0`, or agents running in Windows, you need to install the secret backend manually: Follow the [manual installation](https://github.com/DataDog/datadog-secret-backend#installation) instructions below.
2. Configure the backend type and its settings: Refer to the [supported backends](https://github.com/DataDog/datadog-secret-backend#supported-backends) section for more information. 
    1. You should reference secrets in your datadog.yaml file using the ENC[backend_id:secret_id] format. Here is [more information](https://docs.datadoghq.com/agent/configuration/secrets-management/?tab=linux#how-it-works) on how this works. 
    2. Any necessary configuration will be specified in a file named `datadog-secret-backend.yaml` which should be located in the same directory as the installed `datadog-secret-backend` executable. 

## Supported Backends

| Backend | Provider | Description |
| :-- | :-- | :-- |
| [aws.secrets](docs/aws/secrets.md) | [aws](docs/aws/README.md) | Datadog secrets in AWS Secrets Manager |
| [aws.ssm](docs/aws/ssm.md) | [aws](docs/aws/README.md) | Datadog secrets in AWS Systems Manager Parameter Store |
| [azure.keyvault](docs/azure/keyvault.md) | [azure](docs/azure/README.md) | Datadog secrets in Azure Key Vault |
| [hashicorp.vault](docs/hashicorp/vault.md) | [hashicorp](docs/hashicorp/README.md) | Datadog secrets in Hashicorp Vault |
| [file.json](docs/file/json.md) | [file](docs/file/README.md) | Datadog secrets in local JSON files|
| [file.yaml](docs/file/yaml.md) | [file](docs/file/README.md) | Datadog secrets in local YAML files|

## Manual Installation

1. Make a new folder to hold all the files required for this module in one place (in this example will use
   `datadog-secret-backend`:

    ```
    ## Linux
    mkdir -p /etc/datadog-secret-backend

    ## Windows
    mkdir 'C:\Program Files\datadog-secret-backend\'
    ```

2. Download the most recent version of the secret backend module by hitting the latest release endpoint from this repo by running one of the commands below:

    ```
    ## Linux (amd64)
    curl -L https://github.com/DataDog/datadog-secret-backend/releases/download/v0.3.0/datadog-secret-backend-linux-amd64.tar.gz \ 
    -o /tmp/datadog-secret-backend-linux-amd64.tar.gz

    ## Linux (386)
    curl -L https://github.com/DataDog/datadog-secret-backend/releases/download/v0.3.0/datadog-secret-backend-linux-386.tar.gz \ 
    -o /tmp/datadog-secret-backend-linux-386.tar.gz

    ## Windows (amd64)
    Invoke-WebRequest https://github.com/DataDog/datadog-secret-backend/releases/download/v0.3.0/datadog-secret-backend-windows-amd64.zip -OutFile 'C:\Program Files\datadog-secret-backend\datadog-secret-backend-windows-amd64.zip'

    ## Windows (386)
    Invoke-WebRequest https://github.com/DataDog/datadog-secret-backend/releases/download/v0.3.0/datadog-secret-backend-windows-386.zip -OutFile 'C:\Program Files\datadog-secret-backend\datadog-secret-backend-windows-386.zip'
    ```

3. Once you have the file from the github repo, you'll need to unzip it to get the executable:

    ```
    ## Linux (amd64, change end of filename to "386" if needed)
    tar -xvzf /tmp/datadog-secret-backend-linux-amd64.tar.gz \
    -C /etc/datadog-secret-backend

    ## Windows (amd64, change end of filename to "386" if needed)
    Expand-Archive -LiteralPath 'C:\Program Files\datadog-secret-backend\datadog-secret-backend-windows-amd64.zip' -DestinationPath 'C:\Program Files\datadog-secret-backend\'
    ```

4. (Optional) Remove the old tar'd file:

    ```
    ## Linux
    rm /tmp/datadog-secret-backend-linux-amd64.tar.gz

    ## Windows
    Remove-Item 'C:\Program Files\datadog-secret-backend\datadog-secret-backend-windows-amd64.zip'
    ```

5. Update the executable to have the required [Agent security permissions](https://docs.datadoghq.com/agent/configuration/secrets-management/#agent-security-requirements).

6. [Provide an executable path](https://docs.datadoghq.com/agent/configuration/secrets-management/?tab=linux#providing-an-executable) to the datadog agent via the main `datadog.yaml` file using the `secret_backend_command` variable:

    ```
    ## datadog.yaml ##

    secret_backend_command: /etc/datadog-secret-backend/datadog-secret-backend
    ```

 7. [Provide a configuration](https://github.com/DataDog/datadog-secret-backend/blob/main/datadog-secret-backend.yaml.example) for the secrets executable. Documentation for each supported provider can be found [here](https://github.com/DataDog/datadog-secret-backend/tree/main/docs).

## Usage

Reference each supported backend type's documentation on specific usage examples and configuration options.

## License

[BSD-3-Clause License](LICENSE)
