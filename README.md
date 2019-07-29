# snyk-buildkite-plugin
Buildkite plugin for running Snyk scans

## Example
```yml
steps:
  - name: "Snyk testing"
    plugins:
      - seek-oss/aws-sm#v0.0.5:
          env:
            SNYK_TOKEN: snyk-service-user-api-key
      - seek-oss/snyk#v1.0.0:
          block: true
          language: node
          path: package.json
          severity: low
          npmToken: NPM_TOKEN
          org: test-team
    agents: 
      queue: "security-prod:cicd"
```

## Configuration
**Note** At this stage, the plugin requires the Snyk API key to be stored in the agent environment variable SNYK_TOKEN. It is advised to use the [aws-sm-buildkite-plugin](https://github.com/seek-oss/aws-sm-buildkite-plugin) to pull the key from AWS Secrets Manager. For the POC/development phase, users can store a Snyk API key in their own instance of AWS Secrets Manager.

### `block` (optional)
Whether the build will block if vulnerabilities are found. 

Values: true, false (defaults to true)

### `language` (required)
The language/framework being tested for dependency vulnerabilities

Values: node, dotnet

### `path` (optional)
The path to the dependency file from the root of the repository
For node repositories, specifying the path to package-json.lock or yarn.lock is the preferred method.

Example: package.json (defaults to looking in the root directory)

### `severity` (optional)
The minimum severity results to show

Values: low, medium, high

Example: low will show all low, medium, and high severities

### `scanDevDeps` (optional)
Scan prod AND dev dependencies

Values: true, false

### `npmToken` (optional)
The name of the environment variable containing an NPM token required to pull private packages.
Note: this field is not required when specifying a yarn or npm lockfile in the path field, as Snyk can scan the full dependency tree.

This value can be passed using the [private-npm-buildkite-plugin](https://github.com/seek-oss/private-npm-buildkite-plugin)

### `org` (required)
The organisation (logical group) to which the build pipeline belongs

Examples: team-name-a, team-name-b

### `subDirectory` (optional) (mainly for testing)
Specify a sub directory within the Git repository as the root directory for Snyk scanning.
This is useful for repositories with submodules.

Example: submodule-a, submodule-b

### `packageManager` (optional)
Specify the specific package manager used for dependencies being tested.
This is useful for scanning dependencies in monorepos.

Example: pip