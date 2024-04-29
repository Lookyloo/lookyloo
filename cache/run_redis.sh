#!/bin/bash

set -e
set -x

if [ -f  ../../valkey/src/valkey-server ]; then
    ../../valkey/src/valkey-server ./cache.conf
else
    ../../redis/src/redis-server ./cache.conf
fi
