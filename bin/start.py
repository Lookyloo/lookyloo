#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from lookyloo.helpers import get_homedir

if __name__ == '__main__':
    # Just fail if the env isn't set.
    get_homedir()
    p = Popen(['run_backend.py', '--start'])
    p.wait()
    Popen(['async_scrape.py'])
    Popen(['start_website.py'])
