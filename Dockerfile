FROM python:3.7.4-alpine3.10

ENV SBT_VERSION 1.3.0
ENV PATH=$PATH:/root/.local/bin:/usr/local/sbt/bin

RUN apk update && apk add --update npm jq go libc-dev openjdk8
RUN apk add --no-cache nss bash ncurses
RUN npm config set unsafe-perm true
RUN npm install -g snyk
RUN pip install boto3
RUN apk add --no-cache --virtual=build-dependencies curl wget tar && \
  curl -sL "https://piccolo.link/sbt-$SBT_VERSION.tgz" | gunzip | tar -x -C /usr/local && \
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
