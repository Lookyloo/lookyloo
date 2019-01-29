#!/bin/bash

# set -e
set -x

../../redis/src/redis-cli -s ./cache.sock shutdown
