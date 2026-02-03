#!/usr/bin/env python3

from __future__ import annotations

import configparser
import dataclasses
import gzip
import hashlib
import json
import logging
import os
import pickle
import re
import time

from datetime import datetime, timedelta, date
from functools import lru_cache, cache
from importlib.metadata import version
from io import BufferedIOBase
from logging import Logger
from pathlib import Path
from pydantic import field_validator
from pydantic_core import from_json
from string import punctuation
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import requests

from har2tree import CrawledTree, HostNode, URLNode
from lacuscore import CaptureSettings as LacuscoreCaptureSettings
from PIL import Image
from playwrightcapture import get_devices
from pytaxonomies import Taxonomies  # type: ignore[attr-defined]
import ua_parser
from werkzeug.user_agent import UserAgent
from werkzeug.utils import cached_property

from .default import get_homedir, safe_create_dir, get_config, LookylooException
from .exceptions import NoValidHarFile, TreeNeedsRebuild

if TYPE_CHECKING:
    from .indexing import Indexing

logger = logging.getLogger('Lookyloo - Helpers')


def global_proxy_for_requests() -> dict[str, str]:
    if global_proxy := get_config('generic', 'global_proxy'):
        if global_proxy.get('enable'):
            if not global_proxy.get('server'):
                raise LookylooException('Global proxy is enabled, but no server is set.')
            parsed_url = urlparse(global_proxy['server'])
            if global_proxy.get('username') and global_proxy.get('password'):
                parsed_url['username'] = global_proxy['username']
                parsed_url['password'] = global_proxy['password']
            return {
                'http': urlunparse(parsed_url),
                'https': urlunparse(parsed_url)
            }
    return {}


def prepare_global_session() -> requests.Session:
    session = requests.Session()
    session.headers['user-agent'] = get_useragent_for_requests()
    if proxies := global_proxy_for_requests():
        session.proxies.update(proxies)
    return session


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
def get_captures_dir() -> Path:
    capture_dir = get_homedir() / 'scraped'
    safe_create_dir(capture_dir)
    return capture_dir


@lru_cache
def get_email_template() -> str:
    with (get_homedir() / 'config' / 'email.tmpl').open() as f:
        return f.read()


@lru_cache
def get_tt_template() -> str:
    with (get_homedir() / 'config' / 'tt_readme.tmpl').open() as f:
        return f.read()


@lru_cache
def get_error_screenshot() -> Image.Image:
    error_img: Path = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
    return Image.open(error_img)


# NOTE: do not cache that, otherwise we need to restart the webserver when changing the file.
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
            if not list(self.path.glob('**/*.json')):
                # If the user agents directory containing the users agents gathered by lookyloo is empty, we use the default one.
                logger.warning(f'No user agents found in {self.path}, using default list.')
                self.path = get_homedir() / 'user_agents'
        else:
            self.path = get_homedir() / 'user_agents'

        # This call *must* be here because otherwise, we get the devices from within the async
        # process and as we already have a playwright context, it fails.
        # it is not a problem to have it here because the devices do not change
        # until we have a new version playwright, and restart everything anyway.
        self.playwright_devices = get_devices()

        if ua_files_path := sorted(self.path.glob('**/*.json'), reverse=True):
            self._load_newest_ua_file(ua_files_path[0])
        else:
            self._load_playwright_devices()

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
        # Try to get todays file. only use glob if it doesn't exist.
        today = date.today()
        today_file = self.path / str(today.year) / f"{today.month:02}" / f'{today.year}-{today.month:02}-{today.day}.json'
        yesterday_file = self.path / str(today.year) / f"{today.month:02}" / f'{today.year}-{today.month:02}-{today.day - 1}.json'
        if today_file.exists():
            to_check = today_file
        elif yesterday_file.exists():
            to_check = yesterday_file
        else:
            to_check = sorted(self.path.glob('**/*.json'), reverse=True)[0]

        if to_check != self.most_recent_ua_path:
            self._load_newest_ua_file(to_check)
        return self.most_recent_uas

    @property
    def default(self) -> dict[str, str]:
        '''The default useragent for desktop firefox from playwright'''
        # 2025-12-26: New feature default device picked from the known devices in Playwright.
        default_device_name = get_config('generic', 'default_device_name')
        # check if the device name exists, ignore and warn if not.
        if default_device_name in self.playwright_devices['desktop']['default']:
            default_ua = self.playwright_devices['desktop']['default'][default_device_name]['user_agent']
            default_device_type = 'desktop'
        elif default_device_name in self.playwright_devices['mobile']['default']:
            default_ua = self.playwright_devices['mobile']['default'][default_device_name]['user_agent']
            default_device_type = 'mobile'
        # elif default_device_name in self.playwright_devices['mobile']['landscape']:
        #     default_ua = self.playwright_devices['mobile']['landscape'][default_device_name]['user_agent']
        else:
            default_device_type = 'desktop'
            default_device_name = 'Desktop Chrome'
            default_ua = self.playwright_devices['desktop']['default'][default_device_name]['user_agent']
            logger.warning(f'Unable to find "{default_device_name}" in the devices proposed by Playwright, falling back to default: "Desktop Chrome" / "{default_ua}".')
        parsed_ua = ParsedUserAgent(default_ua)
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
                'useragent': parsed_ua.string,
                'default_device_type': default_device_type,
                'default_device_name': default_device_name}


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
    def _details(self) -> ua_parser.DefaultedResult:
        return ua_parser.parse(self.string).with_defaults()

    @property
    def platform(self) -> str | None:  # type: ignore[override]
        return self._details.os.family

    @property
    def platform_version(self) -> str | None:
        return self._aggregate_version(self._details.os)

    @property
    def browser(self) -> str | None:  # type: ignore[override]
        return self._details.user_agent.family

    @property
    def version(self) -> str | None:  # type: ignore[override]
        return self._aggregate_version(self._details.user_agent)

    def _aggregate_version(self, details: ua_parser.OS | ua_parser.UserAgent) -> str | None:
        return '.'.join(
            part
            for key in ('major', 'minor', 'patch', 'patch_minor')
            if (part := dataclasses.asdict(details).get(key)) is not None
        )

    def __str__(self) -> str:
        return f'OS: {self.platform} - Browser: {self.browser} {self.version} - UA: {self.string}'


class CaptureSettings(LacuscoreCaptureSettings):
    '''The capture settings that can be passed to Lookyloo'''
    listing: bool = get_config('generic', 'default_public')
    not_queued: bool = False
    auto_report: bool | dict[str, str] | None = None  # {'email': , 'comment':}
    dnt: str | None = None
    browser_name: str | None = None
    os: str | None = None
    parent: str | None = None
    remote_lacus_name: str | None = None
    categories: list[str] | None = None

    @field_validator('auto_report', mode='before')
    @classmethod
    def load_auto_report_json(cls, v: Any) -> bool | dict[str, str] | None:
        if isinstance(v, str):
            if v.isdigit():
                return bool(v)
            elif v.startswith('{'):
                return from_json(v)
        elif isinstance(v, dict):
            return v
        return v

    @field_validator('cookies', mode='before')
    @classmethod
    def load_cookies(cls, v: Any) -> list[dict[str, Any]] | None:
        # NOTE: Lookyloo can get the cookies in somewhat weird formats, mornalizing them
        if v:
            return load_cookies(v)
        return None


@lru_cache(64)
def load_user_config(username: str) -> dict[str, Any] | None:
    if any(c in punctuation for c in username):
        # The username is invalid. This should never happen, but let's be safe.
        return None
    user_config_path = get_homedir() / 'config' / 'users' / f'{username}.json'
    if not user_config_path.exists():
        return None
    with user_config_path.open() as _c:
        return json.load(_c)


@cache
def get_indexing(full: bool=False) -> Indexing:
    from .indexing import Indexing
    if get_config('generic', 'index_everything') and full:
        return Indexing(full_index=True)
    return Indexing()


def get_pickle_path(capture_dir: Path | str) -> Path | None:
    if isinstance(capture_dir, str):
        capture_dir = Path(capture_dir)
    pickle_file_gz = capture_dir / 'tree.pickle.gz'
    if pickle_file_gz.exists():
        return pickle_file_gz

    pickle_file = capture_dir / 'tree.pickle'
    if pickle_file.exists():
        return pickle_file

    return None


def remove_pickle_tree(capture_dir: Path) -> None:
    pickle_path = get_pickle_path(capture_dir)
    if pickle_path and pickle_path.exists():
        pickle_path.unlink()


@lru_cache(maxsize=64)
def load_pickle_tree(capture_dir: Path, last_mod_time: int, logger: Logger) -> CrawledTree:
    pickle_path = get_pickle_path(capture_dir)
    tree = None
    try:
        if pickle_path:
            if pickle_path.suffix == '.gz':
                with gzip.open(pickle_path, 'rb') as _pg:
                    tree = pickle.load(_pg)
            else:  # not a GZ pickle
                with pickle_path.open('rb') as _p:
                    tree = pickle.load(_p)
    except pickle.UnpicklingError:
        logger.warning(f'Unpickling error, removing the pickle in {capture_dir}.')
        remove_pickle_tree(capture_dir)
    except EOFError:
        logger.warning(f'EOFError, removing the pickle in {capture_dir}.')
        remove_pickle_tree(capture_dir)
    except FileNotFoundError as e:
        logger.info(f'File not found: {e}')
    except Exception as e:
        logger.exception(f'Unexpected exception when unpickling: {e}')
        remove_pickle_tree(capture_dir)

    if tree:
        try:
            if tree.root_hartree.har.path.exists():
                return tree
            else:
                # The capture was moved.
                remove_pickle_tree(capture_dir)
        except Exception as e:
            logger.warning(f'The pickle is broken, removing: {e}')
            remove_pickle_tree(capture_dir)

    if list(capture_dir.rglob('*.har')) or list(capture_dir.rglob('*.har.gz')):
        raise TreeNeedsRebuild('We have HAR files and need to rebuild the tree.')
    # The tree doesn't need to be rebuilt if there are no HAR files.
    raise NoValidHarFile("Couldn't find HAR files")


def mimetype_to_generic(mimetype: str | None) -> str:
    if not mimetype or mimetype == 'none':
        return 'unset_mimetype'
    elif 'javascript' in mimetype or 'ecmascript' in mimetype or mimetype.startswith('js'):
        return 'js'
    elif (mimetype.startswith('image')
            or mimetype.startswith('img')
            or 'webp' in mimetype):
        return 'image'
    elif mimetype.startswith('text/css'):
        return 'css'
    elif 'json' in mimetype:
        return 'json'
    elif 'html' in mimetype:
        return 'html'
    elif ('font' in mimetype
            or 'woff' in mimetype
            or 'opentype' in mimetype):
        return 'font'
    elif ('octet-stream' in mimetype
            or 'application/x-protobuf' in mimetype
            or 'application/pkix-cert' in mimetype
            or 'application/x-123' in mimetype
            or 'application/x-binary' in mimetype
            or 'application/x-msdownload' in mimetype
            or 'application/x-thrift' in mimetype
            or 'application/x-troff-man' in mimetype
            or 'application/x-typekit-augmentation' in mimetype
            or 'application/grpc-web' in mimetype
            or 'model/gltf-binary' in mimetype
            or 'model/obj' in mimetype
            or 'application/wasm' in mimetype):
        return 'octet-stream'
    elif ('text' in mimetype or 'xml' in mimetype
            or mimetype.startswith('multipart')
            or mimetype.startswith('message')
            or 'application/x-www-form-urlencoded' in mimetype
            or 'application/vnd.oasis.opendocument.formula-template' in mimetype):
        return 'text'
    elif 'video' in mimetype:
        return 'video'
    elif ('audio' in mimetype or 'ogg' in mimetype):
        return 'audio'
    elif ('mpegurl' in mimetype
            or 'application/vnd.yt-ump' in mimetype):
        return 'livestream'
    elif ('application/x-shockwave-flash' in mimetype
            or 'application/x-shockware-flash' in mimetype):  # Yes, shockwaRe
        return 'flash'
    elif 'application/pdf' in mimetype:
        return 'pdf'
    elif ('application/gzip' in mimetype
          or 'application/zip' in mimetype):
        return 'archive'
    elif ('inode/x-empty' in mimetype):
        return 'empty'
    else:
        return 'unknown_mimetype'
