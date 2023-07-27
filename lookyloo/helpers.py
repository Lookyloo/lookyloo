#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import time

from datetime import datetime, timedelta
from functools import lru_cache
from importlib.metadata import version
from io import BufferedIOBase
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse


from har2tree import CrawledTree, HostNode, URLNode
from playwrightcapture import get_devices
from publicsuffixlist import PublicSuffixList  # type: ignore
from pytaxonomies import Taxonomies
from ua_parser import user_agent_parser  # type: ignore
from werkzeug.user_agent import UserAgent
from werkzeug.utils import cached_property

from .default import get_homedir, safe_create_dir, get_config
from .exceptions import LookylooException

logger = logging.getLogger('Lookyloo - Helpers')


# This method is used in json.dump or json.dumps calls as the default parameter:
# json.dumps(..., default=dump_to_json)
def serialize_to_json(obj: Union[Set]) -> Union[List]:
    if isinstance(obj, set):
        return sorted(obj)


def get_resources_hashes(har2tree_container: Union[CrawledTree, HostNode, URLNode]) -> Set[str]:
    if isinstance(har2tree_container, CrawledTree):
        urlnodes = har2tree_container.root_hartree.url_tree.traverse()
    elif isinstance(har2tree_container, HostNode):
        urlnodes = har2tree_container.urls
    elif isinstance(har2tree_container, URLNode):
        urlnodes = [har2tree_container]
    else:
        raise LookylooException(f'har2tree_container cannot be {type(har2tree_container)}')
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
    # TODO (?): fetch the list
    return PublicSuffixList()


@lru_cache(64)
def get_captures_dir() -> Path:
    capture_dir = get_homedir() / 'scraped'
    safe_create_dir(capture_dir)
    return capture_dir


@lru_cache(64)
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


class UserAgents:

    def __init__(self):
        if get_config('generic', 'use_user_agents_users'):
            self.path = get_homedir() / 'own_user_agents'
        else:
            self.path = get_homedir() / 'user_agents'

        ua_files_path = sorted(self.path.glob('**/*.json'), reverse=True)
        # This call *must* be here because otherwise, we get the devices from within the async
        # process and as we already have a playwright context, it fails.
        # it is not a problem to have it here because the devices do not change
        # until we have a new version playwright, and restart everything anyway.
        self.playwright_devices = get_devices()
        self._load_newest_ua_file(ua_files_path[0])

    def _load_newest_ua_file(self, path: Path):
        self.most_recent_ua_path = path
        with self.most_recent_ua_path.open() as f:
            self.most_recent_uas = json.load(f)
            self.by_freq = self.most_recent_uas.pop('by_frequency')
        self._load_playwright_devices()

    def _load_playwright_devices(self):
        # Only get default and desktop for now.
        for device_name, details in self.playwright_devices['desktop']['default'].items():
            parsed_ua = ParsedUserAgent(details['user_agent'])
            if not parsed_ua.platform or not parsed_ua.browser:
                continue
            platform_key = parsed_ua.platform
            if parsed_ua.platform_version:
                platform_key = f'{platform_key} {parsed_ua.platform_version}'
            browser_key = parsed_ua.browser
            if parsed_ua.version:
                browser_key = f'{browser_key} {parsed_ua.version}'
            if platform_key not in self.most_recent_uas:
                self.most_recent_uas[platform_key] = {}
            if browser_key not in self.most_recent_uas[platform_key]:
                self.most_recent_uas[platform_key][browser_key] = []
            if parsed_ua.string in self.most_recent_uas[platform_key][browser_key]:
                self.most_recent_uas[platform_key][browser_key].remove(parsed_ua.string)
            # We want that one at the top of the list.
            self.most_recent_uas[platform_key][browser_key].insert(0, parsed_ua.string)

    @property
    def user_agents(self) -> Dict[str, Dict[str, List[str]]]:
        ua_files_path = sorted(self.path.glob('**/*.json'), reverse=True)
        if ua_files_path[0] != self.most_recent_ua_path:
            self._load_newest_ua_file(ua_files_path[0])
        return self.most_recent_uas

    @property
    def default(self) -> Dict[str, str]:
        '''The default useragent for desktop chrome from playwright'''
        parsed_ua = ParsedUserAgent(self.playwright_devices['desktop']['default']['Desktop Chrome']['user_agent'])
        platform_key = parsed_ua.platform
        if parsed_ua.platform_version:
            platform_key = f'{platform_key} {parsed_ua.platform_version}'
        browser_key = parsed_ua.browser
        if parsed_ua.version:
            browser_key = f'{browser_key} {parsed_ua.version}'
        if not platform_key or not browser_key:
            raise LookylooException(f'Unable to get valid default user agent from playwright: {parsed_ua}')
        return {'os': platform_key,
                'browser': browser_key,
                'useragent': parsed_ua.string}


def load_known_content(directory: str='known_content') -> Dict[str, Dict[str, Any]]:
    to_return: Dict[str, Dict[str, Any]] = {}
    for known_content_file in (get_homedir() / directory).glob('*.json'):
        with known_content_file.open() as f:
            to_return[known_content_file.stem] = json.load(f)
    return to_return


def load_cookies(cookie_pseudofile: Optional[Union[BufferedIOBase, str, bytes, List[Dict[str, Union[str, bool]]]]]=None) -> List[Dict[str, Union[str, bool]]]:
    cookies: List[Dict[str, Union[str, bool]]]
    if cookie_pseudofile:
        if isinstance(cookie_pseudofile, (str, bytes)):
            try:
                cookies = json.loads(cookie_pseudofile)
            except json.decoder.JSONDecodeError as e:
                logger.warning(f'Unable to load json content ({e}): {cookie_pseudofile!r}')
                return []
        elif isinstance(cookie_pseudofile, BufferedIOBase):
            # Note: we might have an empty BytesIO, which is not False.
            try:
                cookies = json.load(cookie_pseudofile)
            except json.decoder.JSONDecodeError as e:
                logger.warning(f'Unable to load json content ({e}): {cookie_pseudofile.read()!r}')
                return []
        else:
            # Already a dict
            cookies = cookie_pseudofile
    else:
        if not (get_homedir() / 'cookies.json').exists():
            return []

        with (get_homedir() / 'cookies.json').open() as f:
            cookies = json.load(f)
    to_return: List[Dict[str, Union[str, bool]]] = []
    try:
        for cookie in cookies:
            to_add: Dict[str, Union[str, bool]]
            if 'Host raw' in cookie and isinstance(cookie['Host raw'], str):
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
                # Cookie from lookyloo/playwright
                to_add = cookie
            to_return.append(to_add)
    except Exception as e:
        logger.warning(f'Unable to load the cookie file: {e} - {cookies}')
    return to_return


def uniq_domains(uniq_urls):
    domains = set()
    for url in uniq_urls:
        splitted = urlparse(url)
        domains.add(splitted.hostname)
    return domains


@lru_cache(64)
def get_useragent_for_requests():
    return f'Lookyloo / {version("lookyloo")}'


def get_cache_directory(root: Path, identifier: str, namespace: Optional[Union[str, Path]] = None) -> Path:
    m = hashlib.md5()
    m.update(identifier.encode())
    digest = m.hexdigest()
    if namespace:
        root = root / namespace
    return root / digest[0] / digest[1] / digest[2] / digest


def is_locked(locked_dir_path: Path, /) -> bool:
    """Check if a capture directory is locked, if the lock is recent enough,
    and if the locking process is still running.

    :param locked_dir_path: Path of the directory.
    """
    lock_file = locked_dir_path / 'lock'
    if not lock_file.exists():
        # No lock file
        return False

    try:
        content = ''
        max_wait_content = 5
        while max_wait_content > 0:
            with lock_file.open('r') as f:
                if content := f.read():
                    break
            # The file is empty, we're between the creation and setting the content
            logger.info(f'Lock file empty ({lock_file}), waiting...')
            max_wait_content -= 1
            time.sleep(1)
        else:
            logger.warning('Lock file empty for too long, removing it.')
            lock_file.unlink(missing_ok=True)
            return False

        ts, pid = content.split(';')
        try:
            os.kill(int(pid), 0)
        except OSError:
            logger.info(f'Lock by dead script {lock_file}, removing it.')
            lock_file.unlink(missing_ok=True)
            return False

        lock_ts = datetime.fromisoformat(ts)
        if lock_ts < datetime.now() - timedelta(minutes=30):
            # Clear old locks. They shouldn't be there, but it's gonna happen.
            logger.info(f'Old lock ({lock_ts.isoformat()}) {lock_file}, removing it.')
            lock_file.unlink(missing_ok=True)
            return False
    except Exception as e:
        logger.critical(f'Lock found, but unable process it: {e}.')
        return False

    # The lockfile is here for a good reason.
    logger.debug(f'Directory locked by {pid}.')
    return True


class ParsedUserAgent(UserAgent):

    # from https://python.tutorialink.com/how-do-i-get-the-user-agent-with-flask/

    @cached_property
    def _details(self):
        return user_agent_parser.Parse(self.string)

    @property
    def platform(self):
        return self._details['os'].get('family')

    @property
    def platform_version(self) -> Optional[str]:
        return self._aggregate_version(self._details['os'])

    @property
    def browser(self):
        return self._details['user_agent'].get('family')

    @property
    def version(self):
        return self._aggregate_version(self._details['user_agent'])

    def _aggregate_version(self, details: Dict[str, str]) -> Optional[str]:
        return '.'.join(
            part
            for key in ('major', 'minor', 'patch', 'patch_minor')
            if (part := details.get(key)) is not None
        )

    def __str__(self):
        return f'OS: {self.platform} - Browser: {self.browser} {self.version} - UA: {self.string}'
