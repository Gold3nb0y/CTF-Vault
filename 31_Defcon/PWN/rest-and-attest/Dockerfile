FROM ubuntu:23.04

RUN apt update
RUN apt install -y socat cargo gdb
RUN apt install -y ncat vim
RUN apt install -y git
RUN git clone https://github.com/longld/peda.git ~/peda && echo "source ~/peda/peda.py" >> ~/.gdbinit
#put it last so that updates are easier
COPY rest-and-attest /rest-and-attest

WORKDIR /rest-and-attest/bin

EXPOSE 4444

