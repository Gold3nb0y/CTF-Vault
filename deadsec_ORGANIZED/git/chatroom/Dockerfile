FROM ubuntu:22.04

RUN apt update && apt install -y socat gcc

COPY server.c /
COPY client.c /

COPY build.sh /

RUN /build.sh

EXPOSE 5000
EXPOSE 5001

COPY init.sh /
COPY start_client.sh /
COPY start_server.sh /

CMD /init.sh
