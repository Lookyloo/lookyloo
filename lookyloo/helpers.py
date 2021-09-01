#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import logging
import json
import pickle
import pkg_resources
from typing import List, Optional, Dict, Union, Any, Set, Tuple
from urllib.parse import urljoin
from io import BufferedIOBase
from pathlib import Path
from datetime import datetime, timedelta
from glob import glob
from urllib.parse import urlparse
from functools import lru_cache
from enum import IntEnum, unique

from har2tree import CrawledTree, HostNode, URLNode
import requests
from requests.exceptions import HTTPError
from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from pytaxonomies import Taxonomies

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
def get_captures_dir() -> Path:
    capture_dir = get_homedir() / 'scraped'
    safe_create_dir(capture_dir)
    return capture_dir


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


def get_socket_path(name: str) -> str:
    mapping = {
        'cache': Path('cache', 'cache.sock'),
        'indexing': Path('indexing', 'indexing.sock'),
        'storage': Path('storage', 'storage.sock'),
    }
    return str(get_homedir() / mapping[name])


def get_user_agents(directory: str='user_agents') -> Dict[str, Any]:
    ua_files_path = str(get_homedir() / directory / '*' / '*' / '*.json')
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


@lru_cache(64)
def get_useragent_for_requests():
    version = pkg_resources.get_distribution('lookyloo').version
    return f'Lookyloo / {version}'


@lru_cache(64)
def get_splash_url() -> str:
    if os.environ.get('SPLASH_URL_DOCKER'):
        # In order to have a working default for the docker image, it is easier to use an environment variable
        return os.environ['SPLASH_URL_DOCKER']
    else:
        return get_config('generic', 'splash_url')


def splash_status() -> Tuple[bool, str]:
    try:
        splash_status = requests.get(urljoin(get_splash_url(), '_ping'))
        splash_status.raise_for_status()
        json_status = splash_status.json()
        if json_status['status'] == 'ok':
            return True, 'Splash is up'
        else:
            return False, str(json_status)
    except HTTPError as http_err:
        return False, f'HTTP error occurred: {http_err}'
    except Exception as err:
        return False, f'Other error occurred: {err}'
