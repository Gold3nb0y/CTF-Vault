FROM livectf/livectf:quals-exploit

COPY solve.py /solve.py
COPY libc.so.6 /libc.so.6
COPY ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2

WORKDIR /
CMD ["python3", "solve.py"]
