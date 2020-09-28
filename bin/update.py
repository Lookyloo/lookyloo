#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import subprocess
import shlex
import sys

from lookyloo.helpers import get_homedir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


def keep_going(ignore=False):
    if ignore:
        return
    keep_going = input('Continue? (y/N) ')
    if keep_going.lower() != 'y':
        print('Okay, quitting.')
        sys.exit()


def run_command(command):
    args = shlex.split(command)
    homedir = get_homedir()
    process = subprocess.run(args, cwd=homedir, capture_output=True)
    print(process.stdout.decode())
    if process.returncode:
        print(process.stderr.decode())
        sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pull latest release, update dependencies, update and validate the config files, update 3rd deps for the website.')
    parser.add_argument('--yes', default=False, action='store_true', help='Run all commands without asking.')
    args = parser.parse_args()

    print('* Update repository.')
    keep_going(args.yes)
    run_command('git pull')

    print('* Install/update dependencies.')
    keep_going(args.yes)
    run_command('poetry install')

    print('* Validate configuration files.')
    keep_going(args.yes)
    run_command('tools/validate_config_files.py --check')

    print('* Update configuration files.')
    keep_going(args.yes)
    run_command('tools/validate_config_files.py --update')

    print('* Update third party dependencies for the website.')
    keep_going(args.yes)
    run_command('tools/3rdparty.py')
