#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from lookyloo.helpers import get_homedir, get_socket_path
from redis import Redis

if __name__ == '__main__':
    get_homedir()
    p = Popen(['shutdown.py'])
    p.wait()
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1)
    r.delete('shutdown')
    Popen(['run_backend.py', '--stop'])
