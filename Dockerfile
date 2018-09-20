FROM python:3.7.0-alpine3.8
RUN apk update && apk add --update npm jq && npm install -g snyk
ENV PATH=$PATH:/root/.local/bin
CMD plugin/snyk.sh