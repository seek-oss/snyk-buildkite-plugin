FROM python:3.7.0-alpine3.8

RUN pip install awscli --upgrade --user
RUN apk add --update npm
RUN apk add --update jq
RUN npm install -g snyk

ENV PATH=$PATH:/root/.local/bin
ENV SNYK_TOKEN ''

COPY . /plugin
WORKDIR /plugin
CMD ./authenticate.sh