#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from lookyloo.helpers import get_homedir
import time

if __name__ == '__main__':
    # Just fail if the env isn't set.
    get_homedir()
    p = Popen(['run_backend.py', '--start'])
    p.wait()
    Popen(['start_website.py'])
