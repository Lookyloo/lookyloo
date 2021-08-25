#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lookyloo.helpers import is_running, get_socket_path
import time
from redis import Redis


def main():
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1)
    r.set('shutdown', 1)
    time.sleep(5)
    while True:
        running = is_running()
        if not running:
            break
        print(running)
        time.sleep(5)


if __name__ == '__main__':
    main()
