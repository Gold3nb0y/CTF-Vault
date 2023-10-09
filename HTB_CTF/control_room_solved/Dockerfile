# FROM ubuntu:22.04
FROM ubuntu@sha256:34fea4f31bf187bc915536831fd0afc9d214755bf700b5cdb1336c82516d154e

# Setup environ
ENV user kana

# Install packages
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirror.kakao.com/g" /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y socat gdb ncat \
 && rm -rf /var/lib/apt/lists/*

# Change permission
RUN chmod 1733 /tmp /var/tmp /dev/shm

# Additional configuration
RUN adduser --disabled-password --gecos "" $user
ADD ./control_room /home/$user/control_room

RUN chown -R root:$user /home/$user/
RUN chown root:$user /home/$user/control_room

RUN chmod 2755 /home/$user/control_room

# final
WORKDIR /home/$user
