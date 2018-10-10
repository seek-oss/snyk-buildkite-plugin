#!/bin/sh
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN

if [[ "$LANGUAGE" = "node" ]];
then
    echo 'Node repository detected'
    echo 'Running npm install!'
    cd $REPOSITORY
    npm install
fi

if [[ "$LANGUAGE" = "golang" ]];
then
    echo 'Go repository detected'
    echo 'Setting up Go'
    export GOPATH='/'

    DIRECTORY=/src/github.com/$REPOSITORY
    mkdir -p $DIRECTORY
    cp -R $REPOSITORY /src/github.com/$REPOSITORY/..
    cd /src/github.com/$REPOSITORY
fi

if [[ "$LANGUAGE" = "scala" ]];
then
    echo 'Scala repository detected'
    echo 'Setting up gradle.properties'
    mkdir ~/.gradle
    GRADLE_PROPERTIES=~/.gradle/gradle.properties
    touch $GRADLE_PROPERTIES
    echo "artifactoryUsername=$ARTIFACTORY_USERNAME" >> $GRADLE_PROPERTIES
    echo "artifactoryPassword=$ARTIFACTORY_PASSWORD" >> $GRADLE_PROPERTIES
    cd $REPOSITORY
fi

if [[ "$LANGUAGE" = "python" ]];
then
    echo 'Python repository detected'
    cd $REPOSITORY
    pip install -r $DEPENDENCY_PATH --user
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
  if [[ "$BLOCK" = true ]]
  then
    exit 1
  fi
  exit 0
fi