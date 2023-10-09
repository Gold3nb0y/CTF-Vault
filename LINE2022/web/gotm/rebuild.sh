#!/bin/bash

sudo docker container stop linectf_gotm
sudo docker container rm linectf_gotm
sudo ./run.sh