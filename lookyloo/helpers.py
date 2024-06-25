#!/usr/bin/env python3

from __future__ import annotations

import configparser
import hashlib
import json
import logging
import os
import re
import time

from datetime import datetime, timedelta, date
from functools import lru_cache
from importlib.metadata import version
from io import BufferedIOBase
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


from har2tree import CrawledTree, HostNode, URLNode
from lacuscore import CaptureSettings as LacuscoreCaptureSettings
from playwrightcapture import get_devices
from publicsuffixlist import PublicSuffixList  # type: ignore[import-untyped]
from pytaxonomies import Taxonomies  # type: ignore[attr-defined]
from ua_parser import user_agent_parser  # type: ignore[import-untyped]
from werkzeug.user_agent import UserAgent
from werkzeug.utils import cached_property

from .default import get_homedir, safe_create_dir, get_config, LookylooException


logger = logging.getLogger('Lookyloo - Helpers')


# This method is used in json.dump or json.dumps calls as the default parameter:
# json.dumps(..., default=dump_to_json)
def serialize_to_json(obj: set[Any]) -> list[Any]:
    if isinstance(obj, set):
        return sorted(obj)


def get_resources_hashes(har2tree_container: CrawledTree | HostNode | URLNode) -> set[str]:
    if isinstance(har2tree_container, CrawledTree):
        urlnodes = har2tree_container.root_hartree.url_tree.traverse()
    elif isinstance(har2tree_container, HostNode):
        urlnodes = har2tree_container.urls
    elif isinstance(har2tree_container, URLNode):
        urlnodes = [har2tree_container]
    else:
        raise LookylooException(f'har2tree_container cannot be {type(har2tree_container)}')
    all_ressources_hashes: set[str] = set()
    for urlnode in urlnodes:
        if hasattr(urlnode, 'resources_hashes'):
            all_ressources_hashes.update(urlnode.resources_hashes)
    return all_ressources_hashes


@lru_cache
def get_taxonomies() -> Taxonomies:
    return Taxonomies()


@lru_cache
def get_public_suffix_list() -> PublicSuffixList:
    """Initialize Public Suffix List"""
    # TODO (?): fetch the list
    return PublicSuffixList()


@lru_cache
def get_captures_dir() -> Path:
    capture_dir = get_homedir() / 'scraped'
    safe_create_dir(capture_dir)
    return capture_dir


@lru_cache
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


@lru_cache(256)
def load_capture_settings(capture_dir: Path) -> CaptureSettings:
    capture_settings_file = capture_dir / 'capture_settings.json'
    if capture_settings_file.exists():
        with capture_settings_file.open() as f:
            return json.load(f)
    return {}


@lru_cache
def load_takedown_filters() -> tuple[re.Pattern[str], re.Pattern[str], dict[str, list[str]]]:
    filter_ini_file = get_homedir() / 'config' / 'takedown_filters.ini'
    if not filter_ini_file.exists():
        raise LookylooException(f'Unable to find the takedown filters file: {filter_ini_file}')
    config = configparser.ConfigParser()
    config.optionxform = str  # type: ignore[method-assign,assignment]
    config.read(filter_ini_file)
    # compile the domains and subdomains to ignore
    ignore_domains_list = []
    for d in [d.strip() for d in config['domain']['ignore'].split('\n') if d.strip()]:
        ignore_domain = f'{d}$'
        ignore_subdomain = rf'.*\.{ignore_domain}'
        ignore_domains_list.append(ignore_domain)
        ignore_domains_list.append(ignore_subdomain)
    ignore_domains = re.compile('|'.join(ignore_domains_list))
    # Compile the emails addresses to ignore
    ignore_emails = re.compile('|'.join([i.strip() for i in config['abuse']['ignore'].split('\n') if i.strip()]))
    # Make the replace list a dictionary
    replace_list = {to_replace: config['replacelist'][to_replace].split(',') for to_replace in config['replacelist']}

    return ignore_domains, ignore_emails, replace_list


def make_dirs_list(root_dir: Path) -> list[Path]:
    directories = []
    year_now = date.today().year
    oldest_year = year_now - 10
    while year_now >= oldest_year:
        year_dir = root_dir / str(year_now)
        if year_dir.exists():
            for month in range(12, 0, -1):
                month_dir = year_dir / f'{month:02}'
                if month_dir.exists():
                    directories.append(month_dir)
        year_now -= 1
    return directories


@lru_cache
def make_ts_from_dirname(dirname: str) -> datetime:
    try:
        return datetime.strptime(dirname, '%Y-%m-%dT%H:%M:%S.%f')
    except ValueError:
        return datetime.strptime(dirname, '%Y-%m-%dT%H:%M:%S')


def get_sorted_captures_from_disk(captures_dir: Path, /, *,
                                  cut_time: datetime | date | None=None,
                                  keep_more_recent: bool=True) -> list[tuple[datetime, Path]]:
    '''Recursively gets all the captures present in a specific directory, doesn't use the indexes.

    NOTE: this method should never be used on archived captures as it's going to take forever on S3
    '''

    all_paths: list[tuple[datetime, Path]] = []
    for entry in captures_dir.iterdir():
        if not entry.is_dir():
            # index file
            continue
        if entry.name.isdigit():
            # sub directory
            all_paths += get_sorted_captures_from_disk(entry, cut_time=cut_time, keep_more_recent=keep_more_recent)
        else:
            # capture directory
            capture_time = make_ts_from_dirname(entry.name)
            if cut_time:
                if keep_more_recent and capture_time >= cut_time:
                    all_paths.append((capture_time, entry))
                elif capture_time < cut_time:
                    # keep only older
                    all_paths.append((capture_time, entry))
            else:
                all_paths.append((capture_time, entry))
    return sorted(all_paths)


class UserAgents:

    def __init__(self) -> None:
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

    def _load_newest_ua_file(self, path: Path) -> None:
        self.most_recent_ua_path = path
        with self.most_recent_ua_path.open() as f:
            self.most_recent_uas = json.load(f)
            self.by_freq = self.most_recent_uas.pop('by_frequency')
        self._load_playwright_devices()

    def _load_playwright_devices(self) -> None:
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
    def user_agents(self) -> dict[str, dict[str, list[str]]]:
        ua_files_path = sorted(self.path.glob('**/*.json'), reverse=True)
        if ua_files_path[0] != self.most_recent_ua_path:
            self._load_newest_ua_file(ua_files_path[0])
        return self.most_recent_uas

    @property
    def default(self) -> dict[str, str]:
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


def load_known_content(directory: str='known_content') -> dict[str, dict[str, Any]]:
    to_return: dict[str, dict[str, Any]] = {}
    for known_content_file in (get_homedir() / directory).glob('*.json'):
        with known_content_file.open() as f:
            to_return[known_content_file.stem] = json.load(f)
    return to_return


def load_cookies(cookie_pseudofile: BufferedIOBase | str | bytes | list[dict[str, str | bool]] | None=None) -> list[dict[str, str | bool]]:
    cookies: list[dict[str, str | bool]]
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
    to_return: list[dict[str, str | bool]] = []
    try:
        for cookie in cookies:
            to_add: dict[str, str | bool]
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


def uniq_domains(uniq_urls: list[str]) -> set[str]:
    domains = set()
    for url in uniq_urls:
        splitted = urlparse(url)
        if splitted.hostname:
            domains.add(splitted.hostname)
    return domains


@lru_cache(64)
def get_useragent_for_requests() -> str:
    return f'Lookyloo / {version("lookyloo")}'


def get_cache_directory(root: Path, identifier: str, namespace: str | Path | None = None) -> Path:
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
                if content := f.read().strip():
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
    except FileNotFoundError:
        logger.debug('Lock found and removed by another process.')
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
    def _details(self) -> dict[str, Any]:
        return user_agent_parser.Parse(self.string)

    @property
    def platform(self) -> str | None:  # type: ignore[override]
        return self._details['os'].get('family')

    @property
    def platform_version(self) -> str | None:
        return self._aggregate_version(self._details['os'])

    @property
    def browser(self) -> str | None:  # type: ignore[override]
        return self._details['user_agent'].get('family')

    @property
    def version(self) -> str | None:  # type: ignore[override]
        return self._aggregate_version(self._details['user_agent'])

    def _aggregate_version(self, details: dict[str, str]) -> str | None:
        return '.'.join(
            part
            for key in ('major', 'minor', 'patch', 'patch_minor')
            if (part := details.get(key)) is not None
        )

    def __str__(self) -> str:
        return f'OS: {self.platform} - Browser: {self.browser} {self.version} - UA: {self.string}'


class CaptureSettings(LacuscoreCaptureSettings, total=False):
    '''The capture settings that can be passed to Lookyloo'''
    listing: int | None
    not_queued: int | None
    auto_report: bool | str | dict[str, str] | None  # {'email': , 'comment': , 'recipient_mail':}
    dnt: str | None
    browser_name: str | None
    os: str | None
    parent: str | None


# overwrite set to True means the settings in the config file overwrite the settings
# provided by the user. False will simply append the settings from the config file if they
# don't exist.
class UserCaptureSettings(CaptureSettings, total=False):
    overwrite: bool


@lru_cache(64)
def load_user_config(username: str) -> UserCaptureSettings | None:
    user_config_path = get_homedir() / 'config' / 'users' / f'{username}.json'
    if not user_config_path.exists():
        return None
    with user_config_path.open() as _c:
        return json.load(_c)
