#!/bin/sh
echo $SNYK_TOKEN # debugging with fake secret - remove for production
echo 'Running snyk.sh'
snyk auth $SNYK_TOKEN

echo 'Running snyk test on:'
ls
snyk test