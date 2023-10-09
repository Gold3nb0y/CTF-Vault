FROM i386/ubuntu:22.04
RUN useradd -m chal
RUN echo "/calc" >/init.sh
RUN apt update && apt install -y socat
COPY calc /

EXPOSE 5000

CMD while [ TRUE ]; do socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/calc; done


