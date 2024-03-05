#!/usr/bin/env python3

from subprocess import Popen, run

from lookyloo.default import get_homedir, get_config


def main() -> None:
    # Just fail if the env isn't set.
    get_homedir()
    print('Start backend (redis)...')
    p = run(['run_backend', '--start'])
    p.check_returncode()
    print('done.')
    print('Start archiving process...')
    Popen(['archiver'])
    print('done.')
    print('Start asynchronous ingestor...')
    Popen(['async_capture'])
    print('done.')
    print('Start background capture builder...')
    Popen(['background_build_captures'])
    print('done.')
    print('Start background indexer...')
    Popen(['background_indexer'])
    print('done.')
    if get_config('generic', 'index_everything'):
        print('Start background full indexer...')
        Popen(['background_full_indexer'])
        print('done.')
    print('Start background processing...')
    Popen(['processing'])
    print('done.')
    print('Start website...')
    Popen(['start_website'])
    print('done.')


if __name__ == '__main__':
    main()
