#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import subprocess
import shlex
import sys
import hashlib

from lookyloo.helpers import get_homedir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


def compute_hash_self():
    m = hashlib.sha256()
    with (get_homedir() / 'bin' / 'update.py').open('rb') as f:
        return m.update(f.read())


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


def check_poetry_version():
    args = shlex.split("poetry self -V")
    homedir = get_homedir()
    process = subprocess.run(args, cwd=homedir, capture_output=True)
    poetry_version_str = process.stdout.decode()
    version = poetry_version_str.split()[2]
    version_details = tuple(int(i) for i in version.split('.'))
    if version_details < (1, 1, 0):
        print('Lookyloo requires poetry >= 1.1.0, please update.')
        print('If you installed with "pip install --user poetry", run "pip install --user -U poetry"')
        print('If you installed via the recommended method, use "poetry self update"')
        print('More details: https://github.com/python-poetry/poetry#updating-poetry')
        sys.exit()


def main():
    parser = argparse.ArgumentParser(description='Pull latest release, update dependencies, update and validate the config files, update 3rd deps for the website.')
    parser.add_argument('--yes', default=False, action='store_true', help='Run all commands without asking.')
    args = parser.parse_args()

    old_hash = compute_hash_self()

    print('* Update repository.')
    keep_going(args.yes)
    run_command('git pull')
    new_hash = compute_hash_self()
    if old_hash != new_hash:
        print('Update script changed, please do "poetry run update"')
        sys.exit()

    check_poetry_version()

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


if __name__ == '__main__':
    main()
