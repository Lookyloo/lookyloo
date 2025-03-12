#!/bin/bash

set -e
set -x

if [ -f ../../kvrocks/build/kvrocks ]; then
    ../../kvrocks/build/kvrocks -c kvrocks.conf
else
    echo 'kvrocks does not seem to be installed locally, using the system-wide install instead.'
    echo 'You can get the DEB package from https://github.com/RocksLabs/kvrocks-fpm/releases'
    kvrocks -c kvrocks.conf
fi
