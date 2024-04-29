#!/bin/bash

set -e
set -x

if [ -f  ../../valkey/src/valkey-server ]; then
    ../../valkey/src/valkey-server ./indexing.conf
else
    ../../redis/src/redis-server ./indexing.conf
fi
