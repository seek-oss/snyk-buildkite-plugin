FROM python:3.7.0-alpine3.8

RUN apk add --update npm
RUN apk add --update jq
RUN npm install -g snyk

ENV PATH=$PATH:/root/.local/bin
CMD plugin/snyk.sh