#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import run, Popen
from lookyloo.helpers import get_homedir


def main():
    # Just fail if the env isn't set.
    get_homedir()
    print('Start backend (redis)...')
    p = run(['run_backend', '--start'])
    p.check_returncode()
    print('done.')
    print('Start asynchronous ingestor...')
    Popen(['async_scrape'])
    print('done.')
    print('Start website...')
    Popen(['start_website'])
    print('done.')


if __name__ == '__main__':
    main()
