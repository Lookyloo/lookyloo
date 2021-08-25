#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import run, Popen
from lookyloo.helpers import get_homedir, get_config, reload_uuids_index


def main():
    # Just fail if the env isn't set.
    get_homedir()
    print('Start backend (redis)...')
    p = run(['run_backend', '--start'])
    p.check_returncode()
    print('done.')
    print('Reload UUIDs index...')
    reload_uuids_index()
    print('done.')
    print('Start asynchronous ingestor...')
    for _ in range(get_config('generic', 'async_capture_processes')):
        Popen(['async_capture'])
    print('done.')
    print('Start background indexer...')
    Popen(['background_indexer'])
    print('done.')
    print('Start background processing...')
    Popen(['processing'])
    print('done.')
    print('Start website...')
    Popen(['start_website'])
    print('done.')


if __name__ == '__main__':
    main()
