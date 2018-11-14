# snyk-buildkite-plugin
Buildkite plugin for running Snyk scans

## Example
```yml
steps:
  - name: "Snyk testing"
    plugins:
      seek-oss/aws-sm#v0.0.5:
        env:
          SNYK_TOKEN: snyk-service-user-api-key
      seek-oss/snyk#v0.0.4:
        block: true
        language: node
        path: package.json
        severity: low
        token: NPM_TOKEN
    agents: 
      queue: "security-prod:cicd"
```

## Configuration
**Note** At this stage, the plugin requires the Snyk API key to be stored in the agent environment variable SNYK_TOKEN. It is advised to use the [aws-sm-buildkite-plugin](https://github.com/seek-oss/aws-sm-buildkite-plugin) to pull the key from AWS Secrets Manager. For the POC/development phase, users can store a Snyk API key in their own instance of AWS Secrets Manager.

### `block` (optional)
Whether the build will block if vulnerabilities are found. 

Values: true, false (defaults to true)

### `language` (optional)
The language/framework being tested for dependency vulnerabilities

Values: node, dotnet

### `path` (optional)
The path to the dependency file from the root of the repository

Example: package.json (defaults to looking in the root directory)

### `severity` (optional)
The minimum severity results to show

Values: low, medium, high

Example: low will show all low, medium, and high severities

### `token` (optional)
The name of the environment variable containing an NPM token required to pull private packages.

This value can be passed using the [private-npm-buildkite-plugin](https://github.com/seek-oss/private-npm-buildkite-plugin)

### `org` (required)
The organisation (logical group) to which the build pipeline belongs 

Examples: team-name-a, team-name-b