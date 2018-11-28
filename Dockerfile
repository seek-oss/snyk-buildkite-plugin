FROM python:3.7.0-alpine3.8
RUN apk update && apk add --update npm jq go libc-dev openjdk8
RUN npm config set unsafe-perm true
RUN npm install -g snyk
RUN pip install boto3
ENV PATH=$PATH:/root/.local/bin
CMD python3 plugin/snyk.py