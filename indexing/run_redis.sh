#!/bin/bash

set -e
set -x

if [ -f  ../../valkey/src/valkey-server ]; then
    ../../valkey/src/valkey-server ./indexing.conf
elif [ -f ../../redis/src/redis-server ]; then
    ../../redis/src/redis-server ./indexing.conf
else
    /usr/bin/redis-server ./indexing.conf

fi
