FROM python:3.7.0-alpine3.8
RUN apk update && apk add --update npm jq go libc-dev openjdk8 && npm install -g snyk
RUN npm config set unsafe-perm true 
ENV PATH=$PATH:/root/.local/bin
CMD plugin/snyk.sh