FROM ubuntu:23.04

COPY ifuckup /

RUN dpkg --add-architecture i386
RUN apt update
RUN apt install -y gdb socat git
RUN chmod +x /ifuckup

RUN git clone https://github.com/longld/peda.git ~/peda && echo "source ~/peda/peda.py" >> ~/.gdbinit

EXPOSE 5000

CMD while [ TRUE ]; do socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/ifuckup; done

