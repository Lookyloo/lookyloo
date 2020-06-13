#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from typing import List, Optional, Dict, Union, Any
from io import BufferedIOBase
from pathlib import Path
from .exceptions import MissingEnv, CreateDirectoryException, ConfigError
from redis import Redis
from redis.exceptions import ConnectionError
from datetime import datetime, timedelta
import time
from glob import glob
import json
import traceback
from urllib.parse import urlparse
import pickle
from har2tree import CrawledTree

from bs4 import BeautifulSoup  # type: ignore
try:
    import cloudscraper  # type: ignore
    HAS_CF = True
except ImportError:
    HAS_CF = False


def get_homedir() -> Path:
    if not os.environ.get('LOOKYLOO_HOME'):
        # Try to open a .env file in the home directory if it exists.
        if (Path(__file__).resolve().parent.parent / '.env').exists():
            with (Path(__file__).resolve().parent.parent / '.env').open() as f:
                for line in f:
                    key, value = line.strip().split('=', 1)
                    if value[0] in ['"', "'"]:
                        value = value[1:-1]
                    os.environ[key] = value

    if not os.environ.get('LOOKYLOO_HOME'):
        guessed_home = Path(__file__).resolve().parent.parent
        raise MissingEnv(f"LOOKYLOO_HOME is missing. \
Run the following command (assuming you run the code from the clonned repository):\
    export LOOKYLOO_HOME='{guessed_home}'")
    return Path(os.environ['LOOKYLOO_HOME'])


def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


def load_configs(path_to_config_files: Optional[Union[str, Path]]=None) -> Dict[str, Dict[str, Any]]:
    if path_to_config_files:
        if isinstance(path_to_config_files, str):
            config_path = Path(path_to_config_files)
        else:
            config_path = path_to_config_files
    else:
        config_path = get_homedir() / 'config'
    if not config_path.exists():
        raise ConfigError(f'Configuration directory {config_path} does not exists.')
    elif not config_path.is_dir():
        raise ConfigError(f'Configuration directory {config_path} is not a directory.')

    to_return = {}
    for path in config_path.glob('*.json'):
        with path.open() as _c:
            to_return[path.stem] = json.load(_c)
    return to_return


def safe_create_dir(to_create: Path) -> None:
    if to_create.exists() and not to_create.is_dir():
        raise CreateDirectoryException(f'The path {to_create} already exists and is not a directory')
    to_create.mkdir(parents=True, exist_ok=True)


def set_running(name: str) -> None:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    r.hset('running', name, 1)


def unset_running(name: str) -> None:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    r.hdel('running', name)


def is_running() -> Dict[Any, Any]:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
    return r.hgetall('running')


def get_socket_path(name: str) -> str:
    mapping = {
        'cache': Path('cache', 'cache.sock'),
        'indexing': Path('indexing', 'indexing.sock'),
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


def update_user_agents() -> None:
    if not HAS_CF:
        # The website with the UAs is behind Cloudflare's anti-bot page, we need cloudscraper
        return

    today = datetime.now()
    ua_path = get_homedir() / 'user_agents' / str(today.year) / f'{today.month:02}'
    safe_create_dir(ua_path)
    ua_file_name: Path = ua_path / f'{today.date().isoformat()}.json'
    if ua_file_name.exists():
        # Already have a UA for that day.
        return
    try:
        s = cloudscraper.create_scraper()
        r = s.get('https://techblog.willshouse.com/2012/01/03/most-common-user-agents/')
    except Exception:
        traceback.print_exc()
        return
    to_store = ua_parser(r.text)
    with open(ua_file_name, 'w') as f:
        json.dump(to_store, f, indent=2)


def ua_parser(html_content: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html_content, 'html.parser')

    try:
        uas = soup.find_all('textarea')[1].text
    except Exception:
        traceback.print_exc()
        return {}

    to_store: Dict[str, Any] = {'by_frequency': []}
    for ua in json.loads(uas):
        os = ua['system'].split(' ')[-1]
        if os not in to_store:
            to_store[os] = {}
        browser = ' '.join(ua['system'].split(' ')[:-1])
        if browser not in to_store[os]:
            to_store[os][browser] = []
        to_store[os][browser].append(ua['useragent'])
        to_store['by_frequency'].append({'os': os, 'browser': browser, 'useragent': ua['useragent']})
    return to_store


def get_user_agents(directory: str='user_agents') -> Dict[str, Any]:
    ua_files_path = str(get_homedir() / directory / '*' / '*' / '*.json')
    paths = sorted(glob(ua_files_path), reverse=True)
    if not paths:
        update_user_agents()
        paths = sorted(glob(ua_files_path), reverse=True)
    with open(paths[0]) as f:
        return json.load(f)


def load_cookies(cookie_pseudofile: Optional[BufferedIOBase]=None) -> List[Dict[str, str]]:
    if cookie_pseudofile:
        cookies = json.load(cookie_pseudofile)
    else:
        if not (get_homedir() / 'cookies.json').exists():
            return []

        with (get_homedir() / 'cookies.json').open() as f:
            cookies = json.load(f)
    to_return = []
    try:
        for cookie in cookies:
            if 'Host raw' in cookie:
                # Cookie export format for Cookie Quick Manager
                u = urlparse(cookie['Host raw']).netloc.split(':', 1)[0]
                to_add = {'path': cookie['Path raw'],
                          'name': cookie['Name raw'],
                          'httpOnly': cookie['HTTP only raw'] == 'true',
                          'secure': cookie['Send for'] == 'Encrypted connections only',
                          'expires': (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%dT%H:%M:%S') + 'Z',
                          'domain': u,
                          'value': cookie['Content raw']
                          }
            else:
                # Cookie from lookyloo/splash
                to_add = cookie
            to_return.append(to_add)
    except Exception as e:
        print(f'Unable to load the cookie file: {e}')
    return to_return


def load_pickle_tree(capture_dir: Path) -> Optional[CrawledTree]:
    pickle_file = capture_dir / 'tree.pickle'
    if pickle_file.exists():
        with pickle_file.open('rb') as _p:
            return pickle.load(_p)
    return None


def remove_pickle_tree(capture_dir: Path) -> None:
    pickle_file = capture_dir / 'tree.pickle'
    if pickle_file.exists():
        pickle_file.unlink()
