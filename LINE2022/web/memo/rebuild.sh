#!/bin/bash

sudo docker container stop linectf_memo
sudo docker container rm linectf_memo
sudo ./run.sh
