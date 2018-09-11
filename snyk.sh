#!/bin/sh
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN
echo 'Running snyk test on:'
ls
snyk test