#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from pathlib import Path
from .exceptions import MissingEnv
from redis import Redis
from redis.exceptions import ConnectionError
from datetime import datetime, timedelta
import time


def get_homedir():
    if not os.environ.get('LOOKYLOO_HOME'):
        guessed_home = Path(__file__).resolve().parent.parent
        raise MissingEnv(f"LOOKYLOO_HOME is missing. \
Run the following command (assuming you run the code from the clonned repository):\
    export LOOKYLOO_HOME='{guessed_home}'")
    return Path(os.environ['LOOKYLOO_HOME'])


def set_running(name: str) -> None:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    r.hset('running', name, 1)


def unset_running(name: str) -> None:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    r.hdel('running', name)


def is_running() -> dict:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    return r.hgetall('running')


def get_socket_path(name: str) -> str:
    mapping = {
        'cache': Path('cache', 'cache.sock'),
        'storage': Path('storage', 'storage.sock'),
    }
    return str(get_homedir() / mapping[name])


def check_running(name: str) -> bool:
    socket_path = get_socket_path(name)
    try:
        r = Redis(unix_socket_path=socket_path)
        if r.ping():
            return True
    except ConnectionError:
        return False


def shutdown_requested() -> bool:
    try:
        r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
        return r.exists('shutdown')
    except ConnectionRefusedError:
        return True
    except ConnectionError:
        return True


def long_sleep(sleep_in_sec: int, shutdown_check: int=10) -> bool:
    if shutdown_check > sleep_in_sec:
        shutdown_check = sleep_in_sec
    sleep_until = datetime.now() + timedelta(seconds=sleep_in_sec)
    while sleep_until > datetime.now():
        time.sleep(shutdown_check)
        if shutdown_requested():
            return False
    return True
