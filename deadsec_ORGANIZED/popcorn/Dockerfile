FROM ubuntu:20.04

RUN apt update && apt install -y gcc gdb socat

COPY popcorn.c /

RUN gcc -o popcorn popcorn.c

RUN echo "BITCH" > /flag

CMD while [ TRUE ]; do socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/popcorn; done
