#!/bin/sh
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN

cd $REPOSITORY

if [[ "$LANGUAGE" = "node" ]];
then
    echo 'Node repository detected'
    echo 'Running npm install!'
    export NPM_TOKEN=$BUILDKITE_PLUGIN_SNYK_TOKEN
    npm install
fi

echo 'Running snyk test!'
if [[ -n "$DEPENDENCY_PATH" ]];
then
    echo 'Explicit path specified'
    echo "Dependency path: $DEPENDENCY_PATH"
    snyk test --file=$DEPENDENCY_PATH --severity-threshold=$SEVERITY
else
    echo 'Explicit path not specified'
    snyk test --severity-threshold=$SEVERITY
fi

snyk_exit_code="$?"

echo 'Running snyk monitor!'
snyk monitor --org=seek-poc # fix after POC phase

if [[ "${snyk_exit_code}" != 0 ]]
then
  echo "Snyk found dependency vulnerabilities"
  if [[ "$BUILDKITE_PLUGIN_SNYK_BLOCK" = true ]]
  then
    exit 1
  fi
  exit 0
fi