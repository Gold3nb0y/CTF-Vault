FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3 python3-bottle vim gdb git && apt-get clean
RUN useradd -d /home/ctf -m ctf

WORKDIR /home/ctf

COPY ./dist/ /home/ctf/
RUN chown -R ctf:ctf /home/ctf

USER ctf
EXPOSE 8080/tcp
#CMD python3 web.py
