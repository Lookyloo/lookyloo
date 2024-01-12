#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from subprocess import Popen
from typing import Optional, Dict

from redis import Redis
from redis.exceptions import ConnectionError

from lookyloo.default import get_homedir, get_socket_path


def check_running(name: str) -> bool:
    socket_path = get_socket_path(name)
    if not os.path.exists(socket_path):
        return False
    try:
        r = Redis(unix_socket_path=socket_path)
        return True if r.ping() else False
    except ConnectionError:
        return False


def launch_cache(storage_directory: Path | None=None) -> None:
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running('cache'):
        Popen(["./run_redis.sh"], cwd=(storage_directory / 'cache'))


def shutdown_cache(storage_directory: Path | None=None) -> None:
    if not storage_directory:
        storage_directory = get_homedir()
    r = Redis(unix_socket_path=get_socket_path('cache'))
    r.shutdown(save=True)
    print('Redis cache database shutdown.')


def launch_indexing(storage_directory: Path | None=None) -> None:
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running('indexing'):
        Popen(["./run_redis.sh"], cwd=(storage_directory / 'indexing'))


def shutdown_indexing(storage_directory: Path | None=None) -> None:
    if not storage_directory:
        storage_directory = get_homedir()
    r = Redis(unix_socket_path=get_socket_path('indexing'))
    r.shutdown(save=True)
    print('Redis indexing database shutdown.')


def launch_all() -> None:
    launch_cache()
    launch_indexing()


def check_all(stop: bool=False) -> None:
    backends: dict[str, bool] = {'cache': False, 'indexing': False}
    while True:
        for db_name in backends.keys():
            try:
                backends[db_name] = check_running(db_name)
            except Exception:
                backends[db_name] = False
        if stop:
            if not any(running for running in backends.values()):
                break
        else:
            if all(running for running in backends.values()):
                break
        for db_name, running in backends.items():
            if not stop and not running:
                print(f"Waiting on {db_name} to start")
            if stop and running:
                print(f"Waiting on {db_name} to stop")
        time.sleep(1)


def stop_all() -> None:
    shutdown_cache()
    shutdown_indexing()


def main() -> None:
    parser = argparse.ArgumentParser(description='Manage backend DBs.')
    parser.add_argument("--start", action='store_true', default=False, help="Start all")
    parser.add_argument("--stop", action='store_true', default=False, help="Stop all")
    parser.add_argument("--status", action='store_true', default=True, help="Show status")
    args = parser.parse_args()

    if args.start:
        launch_all()
    if args.stop:
        stop_all()
    if not args.stop and args.status:
        check_all()


if __name__ == '__main__':
    main()
