#!/bin/sh

# simulates challenge running in production environment
socat tcp4-listen:4444,reuseaddr,fork exec:"./wrapper.sh"
