#!/bin/sh
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN
snyk test