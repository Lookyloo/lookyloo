#!/bin/bash

# set -e
set -x

../../redis/src/redis-cli -s ./indexing.sock shutdown
