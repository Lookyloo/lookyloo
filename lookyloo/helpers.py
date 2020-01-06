#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from pathlib import Path
from .exceptions import MissingEnv, CreateDirectoryException
from redis import Redis
from redis.exceptions import ConnectionError
from datetime import datetime, timedelta
import time
from glob import glob
import json

from bs4 import BeautifulSoup  # type: ignore
try:
    import cfscrape  # type: ignore
    HAS_CF = True
except ImportError:
    HAS_CF = False


def get_homedir() -> Path:
    if not os.environ.get('LOOKYLOO_HOME'):
        guessed_home = Path(__file__).resolve().parent.parent
        raise MissingEnv(f"LOOKYLOO_HOME is missing. \
Run the following command (assuming you run the code from the clonned repository):\
    export LOOKYLOO_HOME='{guessed_home}'")
    return Path(os.environ['LOOKYLOO_HOME'])


def safe_create_dir(to_create: Path):
    if to_create.exists() and not to_create.is_dir():
        raise CreateDirectoryException(f'The path {to_create} already exists and is not a directory')
    os.makedirs(to_create, exist_ok=True)


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
        return True if r.ping() else False
    except ConnectionError:
        return False


def shutdown_requested() -> bool:
    try:
        r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
        return True if r.exists('shutdown') else False
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


def update_user_agents():
    if not HAS_CF:
        # The website with the UAs is behind Cloudflare's anti-bot page, we need cfscrape that depends on nodejs
        return

    today = datetime.now()
    ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
    safe_create_dir(ua_path)
    ua_file_name = ua_path / f'{today.date().isoformat()}.json'
    if ua_file_name.exists():
        # Already have a UA for that day.
        return
    try:
        with cfscrape.create_scraper() as s:
            r = s.get('https://techblog.willshouse.com/2012/01/03/most-common-user-agents/')
    except Exception:
        return
    soup = BeautifulSoup(r.text, 'html.parser')
    uas = soup.find_all('textarea')[1].text
    to_store = {'by_frequency': []}
    for ua in json.loads(uas):
        os = ua['system'].split(' ')[-1]
        if os not in to_store:
            to_store[os] = {}
        browser = ' '.join(ua['system'].split(' ')[:-1])
        if browser not in to_store[os]:
            to_store[os][browser] = []
        to_store[os][browser].append(ua['useragent'])
        to_store['by_frequency'].append({'os': os, 'browser': browser, 'useragent': ua['useragent']})
    with open(ua_file_name, 'w') as f:
        json.dump(to_store, f, indent=2)


def get_user_agents() -> dict:
    ua_files_path = str(get_homedir() / 'user_agents' / '*' / '*' / '*.json')
    paths = sorted(glob(ua_files_path), reverse=True)
    if not paths:
        update_user_agents()
        paths = sorted(glob(ua_files_path), reverse=True)
    with open(paths[0]) as f:
        return json.load(f)
