#!/bin/sh

exec 3<&- 4<&-

exec ./uploader
