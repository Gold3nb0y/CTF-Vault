FROM ubuntu:jammy
COPY open-house /


RUN dpkg --add-architecture i386
RUN apt update
RUN apt install -y gdb git libc6:i386 socat
RUN git clone https://github.com/longld/peda.git ~/peda
RUN echo "source ~/peda/peda.py" >> ~/.gdbinit


EXPOSE 5000
CMD while [ TRUE ]; do socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/open-house; done


