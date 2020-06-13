#!/bin/bash

set -e
set -x

../../redis/src/redis-server ./indexing.conf
