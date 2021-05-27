#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import logging
import time
import json
import traceback
import pickle
from typing import List, Optional, Dict, Union, Any, Set
from io import BufferedIOBase
from pathlib import Path
from datetime import datetime, timedelta
from glob import glob
from urllib.parse import urlparse
from functools import lru_cache
from enum import IntEnum, unique

from har2tree import CrawledTree, HostNode, URLNode
from redis import Redis
from redis.exceptions import ConnectionError
from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from bs4 import BeautifulSoup  # type: ignore
from pytaxonomies import Taxonomies

try:
    import cloudscraper  # type: ignore
    HAS_CF = True
except ImportError:
    HAS_CF = False

from .exceptions import MissingEnv, CreateDirectoryException, ConfigError

configs: Dict[str, Dict[str, Any]] = {}
logger = logging.getLogger('Lookyloo - Helpers')


@unique
class CaptureStatus(IntEnum):
    UNKNOWN = -1
    QUEUED = 0
    DONE = 1
    ONGOING = 2


# This method is used in json.dump or json.dumps calls as the default parameter:
# json.dumps(..., default=dump_to_json)
def serialize_to_json(obj: Union[Set]) -> Union[List]:
    if isinstance(obj, set):
        return list(obj)


def get_resources_hashes(har2tree_container: Union[CrawledTree, HostNode, URLNode]) -> Set[str]:
    if isinstance(har2tree_container, CrawledTree):
        urlnodes = har2tree_container.root_hartree.url_tree.traverse()
    elif isinstance(har2tree_container, HostNode):
        urlnodes = har2tree_container.urls
    elif isinstance(har2tree_container, URLNode):
        urlnodes = [har2tree_container]
    else:
        raise Exception(f'har2tree_container cannot be {type(har2tree_container)}')
    all_ressources_hashes: Set[str] = set()
    for urlnode in urlnodes:
        if hasattr(urlnode, 'resources_hashes'):
            all_ressources_hashes.update(urlnode.resources_hashes)
    return all_ressources_hashes


@lru_cache(64)
def get_taxonomies():
    return Taxonomies()


@lru_cache(64)
def get_public_suffix_list():
    """Initialize Public Suffix List"""
    try:
        psl_file = fetch()
        psl = PublicSuffixList(psl_file=psl_file)
    except Exception:
        psl = PublicSuffixList()
    return psl


@lru_cache(64)
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


@lru_cache(64)
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


@lru_cache(64)
def load_configs(path_to_config_files: Optional[Union[str, Path]]=None):
    global configs
    if configs:
        return
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

    configs = {}
    for path in config_path.glob('*.json'):
        with path.open() as _c:
            configs[path.stem] = json.load(_c)


@lru_cache(64)
def get_config(config_type: str, entry: str, quiet: bool=False) -> Any:
    """Get an entry from the given config_type file. Automatic fallback to the sample file"""
    global configs
    if not configs:
        load_configs()
    if config_type in configs:
        if entry in configs[config_type]:
            return configs[config_type][entry]
        else:
            if not quiet:
                logger.warning(f'Unable to find {entry} in config file.')
    else:
        if not quiet:
            logger.warning(f'No {config_type} config file available.')
    if not quiet:
        logger.warning(f'Falling back on sample config, please initialize the {config_type} config file.')
    with (get_homedir() / 'config' / f'{config_type}.json.sample').open() as _c:
        sample_config = json.load(_c)
    return sample_config[entry]


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
    for ua in json.loads(uas.replace('\n', '')):
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


def load_known_content(directory: str='known_content') -> Dict[str, Dict[str, Any]]:
    to_return: Dict[str, Dict[str, Any]] = {}
    for known_content_file in (get_homedir() / directory).glob('*.json'):
        with known_content_file.open() as f:
            to_return[known_content_file.stem] = json.load(f)
    return to_return


def load_cookies(cookie_pseudofile: Optional[Union[BufferedIOBase, str]]=None) -> List[Dict[str, Union[str, bool]]]:
    cookies: List[Dict[str, Union[str, bool]]]
    if cookie_pseudofile:
        if isinstance(cookie_pseudofile, str):
            cookies = json.loads(cookie_pseudofile)
        else:
            cookies = json.load(cookie_pseudofile)
    else:
        if not (get_homedir() / 'cookies.json').exists():
            return []

        with (get_homedir() / 'cookies.json').open() as f:
            cookies = json.load(f)
    to_return: List[Dict[str, Union[str, bool]]] = []
    try:
        for cookie in cookies:
            to_add: Dict[str, Union[str, bool]]
            if 'Host raw' in cookie:
                # Cookie export format for Cookie Quick Manager
                u = urlparse(cookie['Host raw']).netloc.split(':', 1)[0]  # type: ignore
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
            try:
                return pickle.load(_p)
            except pickle.UnpicklingError:
                remove_pickle_tree(capture_dir)
            except EOFError:
                remove_pickle_tree(capture_dir)
            except Exception:
                remove_pickle_tree(capture_dir)

    return None


def remove_pickle_tree(capture_dir: Path) -> None:
    pickle_file = capture_dir / 'tree.pickle'
    if pickle_file.exists():
        pickle_file.unlink()


def uniq_domains(uniq_urls):
    domains = set()
    for url in uniq_urls:
        splitted = urlparse(url)
        domains.add(splitted.hostname)
    return domains


def try_make_file(filename: Path):
    try:
        filename.touch(exist_ok=False)
        return True
    except FileExistsError:
        return False
