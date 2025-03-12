#!/bin/bash

set -e
set -x

if [ -f ../../kvrocks/build/kvrocks ]; then
    ../../kvrocks/build/kvrocks -c kvrocks.conf
elif [ -x "$(command -v kvrocks)" ]; then
    echo 'kvrocks does not seem to be built locally, using the system-wide install instead.'
    kvrocks -c kvrocks.conf
else
    echo 'kvrocks does not seem to be installed, please install kvrocks and try again.'
    echo 'You can get the DEB package from https://github.com/RocksLabs/kvrocks-fpm/releases'
    exit 1
fi
