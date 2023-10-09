FROM ubuntu:22.04

RUN apt update && apt install -y gcc gdb socat

COPY server.c /
COPY client.c /
COPY build.sh /

COPY init.sh /
COPY start_client.sh /
COPY start_server.sh /

RUN ./build.sh

EXPOSE 5000 5001

CMD ./init.sh
