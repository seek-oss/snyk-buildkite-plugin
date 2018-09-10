#!/bin/sh
echo 'Running snyk.sh'
SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id snyk-service-user-api-key | jq -r '.SecretString')
SECRET_VALUE=$(echo $SECRET_VALUE | sed "s/^[ \t]*//g;s/[ \t]*$//g;s/[\']//g" | jq -r '.snykapikey')
snyk auth $SECRET_VALUE
snyk test