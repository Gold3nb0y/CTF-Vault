from ubuntu:22.04

RUN apt update && apt install -y socat git gdb python3 python-pip 

EXPOSE 9001

RUN mkdir /roppenheimer

COPY roppenheimer_patched /roppenheimer/
COPY libc.so.6 /roppenheimer/
COPY solve.py /roppenheimer/

cmd while sleep 1;do socat TCP-LISTEN:9001,reuseaddr,fork EXEC:/roppenheimer/roppenheimer_patched ;done)
