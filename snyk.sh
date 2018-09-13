#!/bin/sh
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN

echo 'Running npm install!'
cd $REPOSITORY
npm install

echo 'Running snyk test!'
snyk test