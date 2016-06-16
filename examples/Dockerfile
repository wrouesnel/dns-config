FROM ubuntu:wily

RUN apt-get update && apt-get install -y dnsmasq-base dnsutils

COPY [ "start.sh", "example.conf", "/" ]
COPY dns-config /usr/bin/dns-config


CMD [ "/start.sh" ]
