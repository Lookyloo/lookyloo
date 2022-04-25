#!/usr/bin/env python3
import hashlib
import json
import logging
import pkg_resources

from datetime import datetime, timedelta
from enum import IntEnum, unique
from functools import lru_cache
from io import BufferedIOBase
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse


from har2tree import CrawledTree, HostNode, URLNode
from publicsuffix2 import PublicSuffixList, fetch  # type: ignore
from pytaxonomies import Taxonomies
from ua_parser import user_agent_parser  # type: ignore
from werkzeug.user_agent import UserAgent
from werkzeug.utils import cached_property

from .default import get_homedir, safe_create_dir

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
def get_captures_dir() -> Path:
    capture_dir = get_homedir() / 'scraped'
    safe_create_dir(capture_dir)
    return capture_dir


@lru_cache(64)
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


def get_user_agents(directory: str='user_agents') -> Dict[str, Any]:
    ua_files_path = sorted((get_homedir() / directory).glob('**/*.json'), reverse=True)
    with ua_files_path[0].open() as f:
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
            try:
                cookies = json.loads(cookie_pseudofile)
            except json.decoder.JSONDecodeError:
                logger.warning(f'Unable to load json content: {cookie_pseudofile}')
                return []
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
                # Cookie from lookyloo/playwright
                to_add = cookie
            to_return.append(to_add)
    except Exception as e:
        print(f'Unable to load the cookie file: {e}')
    return to_return


def uniq_domains(uniq_urls):
    domains = set()
    for url in uniq_urls:
        splitted = urlparse(url)
        domains.add(splitted.hostname)
    return domains


@lru_cache(64)
def get_useragent_for_requests():
    version = pkg_resources.get_distribution('lookyloo').version
    return f'Lookyloo / {version}'


def get_cache_directory(root: Path, identifier: str, namespace: Optional[str] = None) -> Path:
    m = hashlib.md5()
    m.update(identifier.encode())
    digest = m.hexdigest()
    if namespace:
        root = root / namespace
    return root / digest[0] / digest[1] / digest[2] / digest


class ParsedUserAgent(UserAgent):

    # from https://python.tutorialink.com/how-do-i-get-the-user-agent-with-flask/

    @cached_property
    def _details(self):
        return user_agent_parser.Parse(self.string)

    @property
    def platform(self):
        return self._details['os'].get('family')

    @property
    def browser(self):
        return self._details['user_agent'].get('family')

    @property
    def version(self):
        return '.'.join(
            part
            for key in ('major', 'minor', 'patch')
            if (part := self._details['user_agent'][key]) is not None
        )
