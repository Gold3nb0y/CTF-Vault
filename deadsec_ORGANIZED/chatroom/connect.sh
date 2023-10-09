#!/bin/bash
docker exec -it $(docker ps | head -n 2 | tail -n 1 | awk '{print $1}') /bin/bash
