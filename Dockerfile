FROM python:3.7.13-alpine3.15

ENV SBT_VERSION 1.6.2
ENV PATH=$PATH:/root/.local/bin:/usr/local/sbt/bin

RUN apk update && apk add --update npm jq go libc-dev openjdk8
RUN apk add --no-cache nss bash ncurses git
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install -g snyk
RUN pip install boto3
RUN apk add --no-cache --virtual=build-dependencies curl wget tar && \
  curl -fsL "https://github.com/sbt/sbt/releases/download/v$SBT_VERSION/sbt-$SBT_VERSION.tgz" | gunzip | tar -x -C /usr/local && \
  ln -s /usr/local/sbt/bin/sbt /usr/local/bin/sbt && \
  chmod 0755 /usr/local/bin/sbt && \
  mkdir -p /tmp/sbt-preload && \
  cd /tmp/sbt-preload && \
  touch build.sbt && \
  mkdir -p project && \
  echo "sbt.version=$SBT_VERSION" > project/build.properties && \
  sbt exit && \
  apk del build-dependencies && \
  rm -rf /tmp/*

CMD python3 plugin/snyk.py
