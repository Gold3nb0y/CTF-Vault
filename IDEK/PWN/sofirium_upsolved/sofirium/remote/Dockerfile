FROM ubuntu:22.04

## General stuff
RUN apt update && apt upgrade
RUN apt-get install qemu-system-x86 -y
RUN apt-get install socat -y
RUN /usr/sbin/useradd --no-create-home -u 1000 user

## Challenge files
COPY ./bzImage /home/user/
COPY ./initramfs.cpio /home/user/
COPY run.sh /home/user/
COPY ./run.py /home/user/

WORKDIR "/home/user"

USER user

CMD socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"python3 /home/user/run.py"
