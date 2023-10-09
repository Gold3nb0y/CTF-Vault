#!/bin/bash
#
chef=`docker ps | tail -n 1 | awk '{print $1}'`
docker kill "$chef"

