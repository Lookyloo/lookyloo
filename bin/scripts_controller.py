#!/usr/bin/env python3

from __future__ import annotations

import argparse

import time

from subprocess import Popen

from psutil import Process
from redis import Redis

from lookyloo.default import get_homedir, get_socket_path, AbstractManager


def _get_cmdline(pid: str) -> list[str]:
    process = Process(int(pid))
    return process.cmdline()


def main() -> None:
    parser = argparse.ArgumentParser(description='Manage the scripts.')
    parser.add_argument('action', choices=['list', 'stop', 'restart'], help='The action to perform.', default='list')
    parser.add_argument('script', help='The script to manage.', nargs='?')
    args = parser.parse_args()
    # Just fail if the env isn't set.
    get_homedir()
    if args.action == 'list':
        try:
            print(AbstractManager.is_running())
        except FileNotFoundError:
            print('Redis is down.')
    else:
        # we need to keep the cmdline for the restart
        # And if it doesn't exist, we want to inform the user.
        for name, numbers, pids in AbstractManager.is_running():
            if name == args.script:
                to_restart = _get_cmdline(pids.pop())
                break
        else:
            print(f'{args.script} is not running or does not exists.')
            to_restart = []

        print(f'Request {args.script} to {args.action}...')
        r = Redis(unix_socket_path=get_socket_path('cache'), db=1)
        r.sadd('shutdown_manual', args.script)
        while r.zscore('running', args.script) is not None:
            print(f'Wait for {args.script} to stop...')
            time.sleep(1)
        print('done.')
        r.srem('shutdown_manual', args.script)

        if args.action == 'restart' and to_restart:
            print(f'Start {args.script}...')
            Popen(to_restart)
            print('done.')


if __name__ == '__main__':
    main()
