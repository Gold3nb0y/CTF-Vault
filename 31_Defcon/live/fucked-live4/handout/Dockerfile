FROM livectf/livectf:quals-socat

COPY challenge /home/livectf/
COPY run.sh /home/livectf/
COPY config.toml /home/livectf/.config.toml

RUN chmod 440 /home/livectf/.config.toml
RUN apt update
RUN apt install -y socat

CMD /home/livectf/run.sh
