while [ TRUE ]; do socat TCP-LISTEN:31337,reuseaddr,fork EXEC:/home/livectf/challenge; done

