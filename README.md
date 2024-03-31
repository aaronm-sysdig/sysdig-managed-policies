# Disclaimer
Notwithstanding anything that may be contained to the contrary in your agreement(s) with Sysdig, Sysdig provides no support, no updates, and no warranty or guarantee of any kind with respect to these script(s), including as to their functionality or their ability to work in your environment(s). Sysdig disclaims all liability and responsibility with respect to any use of these scripts.

# Sysdig Managed Policies Importer

Sysdig Managed Policies Importer is a command-line tool developed in Go, designed to automate the import and management of Sysdig Falco security policies. This tool streamlines the process of deploying standardized security policies across different environments, making it easier for teams to ensure consistent security postures.

## Features

- **Policy Import**: Automatically imports a predefined set of Sysdig Falco security policies based off the Falco rules tagged in the branch
- **Configuration Flexibility**: Customize policy names with a Prefix and/or Suffix along with enable/disable the policies through command-line parameters or environment variables.
- **Sysdig API Integration**: Creates these policies directly into your OnPrem environment

## Getting Started


### Prerequisites
- Go version 1.18 or later
- Access to a Sysdig account with API token

### Installation

Clone the repository and build the application:

```bash
git clone https://github.com/aaronm-sysdig/sysdig-managed-policies.git
cd sysdig-managed-policies
go build .
```

### Usage

Run the application with the necessary flags or environment variables:

```bash
./sysdig-managed-policies [flags]
```

## Parameters

The tool supports several command-line parameters to customize its behavior. The following table outlines these parameters, their descriptions, and their corresponding environment variable counterparts when applicable.

| Parameter              | Description                           | Environment Variable    | Default Value |
|------------------------|---------------------------------------|-------------------------|---------------|
| `-e, --enabled`        | Enable Polices                        |                         | `false`       |
| `-a, --sysdig-api-endpoint` | Sysdig API Endpoint              | `SYSDIG_API_ENDPOINT`   |               |
| `-k, --secure-api-token`   | Sysdig API Token                   | `SECURE_API_TOKEN`      |               |
| `-p, --prefix`         | Sysdig Policy Prefix                  |                         |               |
| `-s, --suffix`         | Sysdig Policy Suffix                  |                         |               |

**Note**: Parameters with an associated environment variable can be configured either via the command line or by setting the environment variable.  Presedence is given to the command line variable

### Examples

Run the importer with a specific API token and endpoint:

```bash
./sysdig-managed-policies-importer --enabled --sysdig-api-endpoint "https://api.sysdig.com" --secure-api-token "your_api_token_here"
```

Alternatively, use environment variables:

```bash
export SYSDIG_API_ENDPOINT="https://api.sysdig.com"
export SECURE_API_TOKEN="your_api_token_here"
./sysdig-managed-policies-importer --enabled
```

## Contributing

We welcome contributions! Please feel free to submit pull requests or open issues to improve the tool or suggest new features.
