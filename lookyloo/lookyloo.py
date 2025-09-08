#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import gzip
import ipaddress
import itertools
import json
import logging
import operator
import shutil
import re
import smtplib
import ssl
import time

from base64 import b64decode, b64encode
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from functools import cached_property
from io import BytesIO
from pathlib import Path
from typing import Any, TYPE_CHECKING, overload, Literal
from collections.abc import Iterable
from urllib.parse import urlparse, unquote_plus
from uuid import uuid4
from zipfile import ZipFile, ZIP_DEFLATED

import certifi
import cryptography.exceptions
import mmh3

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from defang import defang  # type: ignore[import-untyped]
from har2tree import CrawledTree, HostNode, URLNode, Har2TreeError
from lacuscore import (LacusCore, CaptureSettingsError,
                       CaptureStatus as CaptureStatusCore,
                       # CaptureResponse as CaptureResponseCore)
                       # CaptureResponseJson as CaptureResponseJsonCore,
                       # CaptureSettings as CaptureSettingsCore
                       )
from PIL import Image, UnidentifiedImageError
from playwrightcapture import get_devices
from puremagic import from_string, PureError
from pylacus import (PyLacus,
                     CaptureStatus as CaptureStatusPy
                     # CaptureResponse as CaptureResponsePy,
                     # CaptureResponseJson as CaptureResponseJsonPy,
                     # CaptureSettings as CaptureSettingsPy
                     )
from pymisp import MISPAttribute, MISPEvent, MISPObject
from pysecuritytxt import PySecurityTXT, SecurityTXTNotAvailable
from pylookyloomonitoring import PyLookylooMonitoring
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection
from rfc3161_client import (TimeStampResponse, VerifierBuilder, VerificationError,
                            decode_timestamp_response)

from .capturecache import CaptureCache, CapturesIndex
from .context import Context
from .default import (LookylooException, get_homedir, get_config, get_socket_path,
                      ConfigError, safe_create_dir)
from .exceptions import (MissingCaptureDirectory,
                         MissingUUID, TreeNeedsRebuild, NoValidHarFile, LacusUnreachable)
from .helpers import (get_captures_dir, get_email_template,
                      get_resources_hashes, get_taxonomies,
                      uniq_domains, ParsedUserAgent, UserAgents,
                      get_useragent_for_requests, load_takedown_filters,
                      global_proxy_for_requests,
                      CaptureSettings, load_user_config,
                      get_indexing, get_error_screenshot
                      )
from .modules import (MISPs, PhishingInitiative, UniversalWhois,
                      UrlScan, VirusTotal, Phishtank, Hashlookup,
                      Pandora, URLhaus, CIRCLPDNS)


if TYPE_CHECKING:
    from playwright.async_api import StorageState
    from playwrightcapture import SetCookieParam as SetCookieParamPWC, Cookie as CookiePWC
    from pylacus.api import SetCookieParam as SetCookieParamPL, Cookie as CookiePL
    SetCookieParams = list[SetCookieParamPWC] | list[SetCookieParamPL]
    Cookies = list[CookiePWC] | list[CookiePL]


class Lookyloo():

    def __init__(self, cache_max_size: int | None=None) -> None:
        '''Initialize lookyloo.
        :param cache_max_size: The maximum size of the cache. Alows to display captures metadata without getting it from redis
                               This cache is *not* useful for background indexing or pickle building, only for the front end.
                               So it should always be None *unless* we're running the background processes.
        '''
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.user_agents = UserAgents()
        self.is_public_instance = get_config('generic', 'public_instance')
        self.public_domain = get_config('generic', 'public_domain')

        self.global_proxy = {}
        if global_proxy := get_config('generic', 'global_proxy'):
            if global_proxy.get('enable'):
                self.global_proxy = copy.copy(global_proxy)
                self.global_proxy.pop('enable')

        self.securitytxt = PySecurityTXT(useragent=get_useragent_for_requests(), proxies=global_proxy_for_requests())
        self.taxonomies = get_taxonomies()

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)
        self.capture_dir: Path = get_captures_dir()

        self._priority = get_config('generic', 'priority')
        self.headed_allowed = get_config('generic', 'allow_headed')

        # Initialize 3rd party components
        # ## Initialize MISP(s)
        try_old_config = False
        # New config
        self.misps = MISPs(config_name='MultipleMISPs')
        if not self.misps.available:
            self.logger.warning('Unable to setup the MISPs module')
            try_old_config = True

        if try_old_config:
            # Legacy MISP config, now use MultipleMISPs key to support more than one MISP instance
            try:
                if misp_config := get_config('modules', 'MISP'):
                    misps_config = {'default': 'MISP', 'instances': {'MISP': misp_config}}
                    self.misps = MISPs(config=misps_config)
                    if self.misps.available:
                        self.logger.warning('Please migrate the MISP config to the "MultipleMISPs" key in the config, and remove the "MISP" key')
                    else:
                        self.logger.warning('Unable to setup the MISP module')
            except Exception:
                # The key was removed from the config, and the sample config
                pass

        # ## Done with MISP(s)

        self.pi = PhishingInitiative(config_name='PhishingInitiative')
        self.vt = VirusTotal(config_name='VirusTotal')
        self.uwhois = UniversalWhois(config_name='UniversalWhois')
        self.urlscan = UrlScan(config_name='UrlScan')
        self.phishtank = Phishtank(config_name='Phishtank')
        self.hashlookup = Hashlookup(config_name='Hashlookup')
        self.pandora = Pandora()
        self.urlhaus = URLhaus(config_name='URLhaus')
        self.circl_pdns = CIRCLPDNS(config_name='CIRCLPDNS')

        self.logger.info('Initializing context...')
        self.context = Context()
        self.logger.info('Context initialized.')
        self.logger.info('Initializing index...')
        self._captures_index = CapturesIndex(self.redis, self.context, maxsize=cache_max_size)
        self.logger.info('Index initialized.')

    @property
    def monitoring(self) -> PyLookylooMonitoring | None:
        self._monitoring: PyLookylooMonitoring | None
        if (not get_config('generic', 'monitoring')
                or not get_config('generic', 'monitoring').get('enable')):
            # Not enabled, break immediately
            return None
        try:
            if hasattr(self, '_monitoring') and self._monitoring and self._monitoring.is_up:
                return self._monitoring
        except TimeoutError:
            self.logger.warning('Monitoring is temporarly (?) unreachable.')
            return None
        monitoring_config = get_config('generic', 'monitoring')
        monitoring = PyLookylooMonitoring(monitoring_config['url'], get_useragent_for_requests(), proxies=global_proxy_for_requests())
        if monitoring.is_up:
            self._monitoring = monitoring
            return self._monitoring
        return None

    @property
    def redis(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.redis_pool)

    def __enable_remote_lacus(self, lacus_url: str) -> PyLacus:
        '''Enable remote lacus'''
        self.logger.info("Remote lacus enabled, trying to set it up...")
        lacus_retries = 2
        while lacus_retries > 0:
            remote_lacus_url = lacus_url
            lacus = PyLacus(remote_lacus_url, useragent=get_useragent_for_requests(),
                            proxies=global_proxy_for_requests())
            if lacus.is_up:
                self.logger.info(f"Remote lacus enabled to {remote_lacus_url}.")
                break
            lacus_retries -= 1
            self.logger.warning(f"Unable to setup remote lacus to {remote_lacus_url}, trying again {lacus_retries} more time(s).")
            time.sleep(3)
        else:
            raise LacusUnreachable(f'Remote lacus ({remote_lacus_url}) is enabled but unreachable.')
        return lacus

    @cached_property
    def lacus(self) -> PyLacus | LacusCore | dict[str, PyLacus]:
        has_remote_lacus = False
        self._lacus: PyLacus | LacusCore | dict[str, PyLacus]
        if get_config('generic', 'remote_lacus'):
            remote_lacus_config = get_config('generic', 'remote_lacus')
            if remote_lacus_config.get('enable'):
                self._lacus = self.__enable_remote_lacus(remote_lacus_config.get('url'))
                has_remote_lacus = True

        if remote_lacus_config := get_config('generic', 'multiple_remote_lacus'):
            # Multiple remote lacus enabled
            if remote_lacus_config.get('enable') and has_remote_lacus:
                raise ConfigError('You cannot use both remote_lacus and multiple_remote_lacus at the same time.')
            if remote_lacus_config.get('enable'):
                self._lacus = {}
                for lacus_config in remote_lacus_config.get('remote_lacus'):
                    try:
                        self._lacus[lacus_config['name']] = self.__enable_remote_lacus(lacus_config['url'])
                    except LacusUnreachable as e:
                        self.logger.warning(f'Unable to setup remote lacus {lacus_config["name"]}: {e}')
                if not self._lacus:
                    raise LacusUnreachable('Unable to setup any remote lacus.')
                # Check default lacus is valid
                default_remote_lacus_name = remote_lacus_config.get('default')
                if default_remote_lacus_name not in self._lacus:
                    raise ConfigError(f'Invalid or unreachable default remote lacus: {default_remote_lacus_name}')
                has_remote_lacus = True

        if not has_remote_lacus:
            # We need a redis connector that doesn't decode.
            redis: Redis = Redis(unix_socket_path=get_socket_path('cache'))  # type: ignore[type-arg]
            self._lacus = LacusCore(redis, tor_proxy=get_config('generic', 'tor_proxy'),
                                    i2p_proxy=get_config('generic', 'i2p_proxy'),
                                    tt_settings=get_config('generic', 'trusted_timestamp_settings'),
                                    max_capture_time=get_config('generic', 'max_capture_time'),
                                    only_global_lookups=get_config('generic', 'only_global_lookups'),
                                    headed_allowed=self.headed_allowed,
                                    loglevel=get_config('generic', 'loglevel'))
        return self._lacus

    def update_cache_index(self) -> None:
        '''Update the cache index with the latest captures'''
        # NOTE: This call is moderately expensive as it iterates over all the non-archived captures
        self._captures_index._quick_init()

    def add_context(self, capture_uuid: str, /, urlnode_uuid: str, *, ressource_hash: str,
                    legitimate: bool, malicious: bool, details: dict[str, dict[str, str]]) -> None:
        '''Adds context information to a capture or a URL node'''
        if malicious:
            self.context.add_malicious(ressource_hash, details['malicious'])
        if legitimate:
            self.context.add_legitimate(ressource_hash, details['legitimate'])

    def add_to_legitimate(self, capture_uuid: str, /, hostnode_uuid: str | None=None, urlnode_uuid: str | None=None) -> None:
        '''Mark a full capture as legitimate.
        Iterates over all the nodes and mark them all as legitimate too.'''
        ct = self.get_crawled_tree(capture_uuid)
        self.context.mark_as_legitimate(ct, hostnode_uuid, urlnode_uuid)

    def remove_pickle(self, capture_uuid: str, /) -> None:
        '''Remove the pickle from a specific capture.'''
        self._captures_index.remove_pickle(capture_uuid)

    def rebuild_cache(self) -> None:
        '''Flush and rebuild the redis cache. Doesn't remove the pickles.
        The cached captures will be rebuild when loading the index.'''
        self.redis.flushdb()

    def rebuild_all(self) -> None:
        '''Flush and rebuild the redis cache, and delete all the pickles.
        The captures will be rebuilt by the background indexer'''
        self._captures_index.rebuild_all()

    def get_urlnode_from_tree(self, capture_uuid: str, /, node_uuid: str) -> URLNode:
        '''Get a URL node from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.get_url_node_by_uuid(node_uuid)

    def get_urlnodes_from_tree(self, capture_uuid: str, /, node_uuids: Iterable[str]) -> list[URLNode]:
        '''Get a list of URL nodes from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return [ct.root_hartree.get_url_node_by_uuid(node_uuid) for node_uuid in node_uuids]

    def get_hostnode_from_tree(self, capture_uuid: str, /, node_uuid: str) -> HostNode:
        '''Get a host node from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_hostnodes_from_tree(self, capture_uuid: str, /, node_uuids: Iterable[str]) -> list[HostNode]:
        '''Get a list of host nodes from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return [ct.root_hartree.get_host_node_by_uuid(node_uuid) for node_uuid in node_uuids]

    def get_statistics(self, capture_uuid: str, /) -> dict[str, Any]:
        '''Get the statistics of a capture.'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.stats

    def get_info(self, capture_uuid: str, /) -> tuple[bool, dict[str, Any]]:
        '''Get basic information about the capture.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return False, {'error': f'Unable to find UUID {capture_uuid} in the cache.'}

        if not hasattr(cache, 'uuid'):
            self.logger.critical(f'Cache for {capture_uuid} is broken: {cache}.')
            return False, {'error': f'Sorry, the capture {capture_uuid} is broken, please report it to the admin.'}

        to_return = {'uuid': cache.uuid,
                     'url': cache.url if hasattr(cache, 'url') else 'Unable to get URL for the capture'}
        if hasattr(cache, 'error') and cache.error:
            to_return['error'] = cache.error
        if hasattr(cache, 'title'):
            to_return['title'] = cache.title
        if hasattr(cache, 'timestamp'):
            to_return['capture_time'] = cache.timestamp.isoformat()
        if hasattr(cache, 'user_agent') and cache.user_agent:
            to_return['user_agent'] = cache.user_agent
        if hasattr(cache, 'referer'):
            to_return['referer'] = cache.referer if cache.referer else ''
        return True, to_return

    def get_meta(self, capture_uuid: str, /) -> dict[str, str]:
        '''Get the meta informations from a capture (mostly, details about the User Agent used.)'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {}
        metafile = cache.capture_dir / 'meta'
        if metafile.exists():
            with metafile.open('r') as f:
                return json.load(f)

        if not cache.user_agent:
            return {}
        meta = {}
        ua = ParsedUserAgent(cache.user_agent)
        meta['user_agent'] = ua.string
        if ua.platform:
            meta['os'] = ua.platform
        if ua.browser:
            if ua.version:
                meta['browser'] = f'{ua.browser} {ua.version}'
            else:
                meta['browser'] = ua.browser

        if not meta:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        with metafile.open('w') as f:
            json.dump(meta, f)
        return meta

    def get_capture_settings(self, capture_uuid: str, /) -> CaptureSettings | None:
        '''Get the capture settings from the cache or the disk.'''
        try:
            if capture_settings := self.redis.hgetall(capture_uuid):
                return CaptureSettings(**capture_settings)
        except CaptureSettingsError as e:
            self.logger.warning(f'Invalid capture settings for {capture_uuid}: {e}')
            raise e
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return None
        return cache.capture_settings

    def categorize_capture(self, capture_uuid: str, /, categories: list[str], *, as_admin: bool=False) -> tuple[set[str], set[str]]:
        '''Add a category (MISP Taxonomy tag) to a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return set(), set()

        # Make sure the category is mappable to the dark-web taxonomy
        valid_categories = set()
        invalid_categories = set()
        for category in categories:
            taxonomy, predicate, name = self.taxonomies.revert_machinetag(category)  # type: ignore[misc]
            if not taxonomy or not predicate or not name and taxonomy.name != 'dark-web':
                self.logger.warning(f'Invalid category: {category}')
                invalid_categories.add(category)
            else:
                valid_categories.add(category)

        if as_admin:
            # Keep categories that aren't a part of the dark-web taxonomy, force the rest
            current_categories = {c for c in self._captures_index[capture_uuid].categories if not c.startswith('dark-web')}
            current_categories |= valid_categories
        else:
            # Only add categories.
            current_categories = self._captures_index[capture_uuid].categories
            current_categories |= valid_categories
        self._captures_index[capture_uuid].categories = current_categories

        get_indexing().reindex_categories_capture(capture_uuid)
        if get_config('generic', 'index_everything'):
            get_indexing(full=True).reindex_categories_capture(capture_uuid)
        return valid_categories, invalid_categories

    def uncategorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Remove a category (MISP Taxonomy tag) from a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = {line.strip() for line in f.readlines()}
        else:
            current_categories = set()
        if category in current_categories:
            current_categories.remove(category)
            with categ_file.open('w') as f:
                f.writelines(f'{t}\n' for t in current_categories)
        get_indexing().reindex_categories_capture(capture_uuid)
        if get_config('generic', 'index_everything'):
            get_indexing(full=True).reindex_categories_capture(capture_uuid)

    def trigger_modules(self, capture_uuid: str, /, force: bool, auto_trigger: bool, *, as_admin: bool) -> dict[str, Any]:
        '''Launch the 3rd party modules on a capture.
        It uses the cached result *if* the module was triggered the same day.
        The `force` flag re-triggers the module regardless of the cache.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': f'UUID {capture_uuid} is either unknown or the tree is not ready yet.'}

        self.uwhois.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        self.hashlookup.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)

        to_return: dict[str, dict[str, Any]] = {'PhishingInitiative': {}, 'VirusTotal': {}, 'UrlScan': {},
                                                'URLhaus': {}}
        to_return['PhishingInitiative'] = self.pi.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        to_return['VirusTotal'] = self.vt.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        to_return['UrlScan'] = self.urlscan.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        to_return['Phishtank'] = self.phishtank.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        to_return['URLhaus'] = self.urlhaus.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger, as_admin=as_admin)
        return to_return

    def get_modules_responses(self, capture_uuid: str, /) -> dict[str, Any]:
        '''Get the responses of the modules from the cached responses on the disk'''
        cache = self.capture_cache(capture_uuid)
        # TODO: return a message when we cannot get the modules responses, update the code checking if it is falsy accordingly.
        if not cache:
            self.logger.warning(f'Unable to get the modules responses unless the capture {capture_uuid} is cached')
            return {}
        if not hasattr(cache, 'url'):
            self.logger.warning(f'The capture {capture_uuid} does not have a URL in the cache, it is broken.')
            return {}

        to_return: dict[str, Any] = {}
        if self.vt.available:
            to_return['vt'] = {}
            if hasattr(cache, 'redirects') and cache.redirects:
                for redirect in cache.redirects:
                    to_return['vt'][redirect] = self.vt.get_url_lookup(redirect)
            else:
                to_return['vt'][cache.url] = self.vt.get_url_lookup(cache.url)
        if self.pi.available:
            to_return['pi'] = {}
            if hasattr(cache, 'redirects') and cache.redirects:
                for redirect in cache.redirects:
                    to_return['pi'][redirect] = self.pi.get_url_lookup(redirect)
            else:
                to_return['pi'][cache.url] = self.pi.get_url_lookup(cache.url)
        if self.phishtank.available:
            to_return['phishtank'] = {'urls': {}, 'ips_hits': {}}
            if hasattr(cache, 'redirects') and cache.redirects:
                for redirect in cache.redirects:
                    to_return['phishtank']['urls'][redirect] = self.phishtank.get_url_lookup(redirect)
            else:
                to_return['phishtank']['urls'][cache.url] = self.phishtank.get_url_lookup(cache.url)
            ips_hits = self.phishtank.lookup_ips_capture(cache)
            if ips_hits:
                to_return['phishtank']['ips_hits'] = ips_hits
        if self.urlhaus.available:
            to_return['urlhaus'] = {'urls': {}}
            if hasattr(cache, 'redirects') and cache.redirects:
                for redirect in cache.redirects:
                    to_return['urlhaus']['urls'][redirect] = self.urlhaus.get_url_lookup(redirect)
            else:
                to_return['urlhaus']['urls'][cache.url] = self.urlhaus.get_url_lookup(cache.url)

        if self.urlscan.available:
            to_return['urlscan'] = {'submission': {}, 'result': {}}
            to_return['urlscan']['submission'] = self.urlscan.get_url_submission(cache)
            if to_return['urlscan']['submission'] and 'uuid' in to_return['urlscan']['submission']:
                # The submission was done, try to get the results
                result = self.urlscan.url_result(cache)
                if 'error' not in result:
                    to_return['urlscan']['result'] = result
        return to_return

    def hide_capture(self, capture_uuid: str, /) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self._captures_index[capture_uuid].capture_dir
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()
        self._captures_index.reload_cache(capture_uuid)

    def remove_capture(self, capture_uuid: str, /) -> None:
        """Remove the capture, it won't be accessible anymore."""

        removed_captures_dir = get_homedir() / 'removed_captures'
        removed_captures_dir.mkdir(parents=True, exist_ok=True)
        capture_dir = self._captures_index[capture_uuid].capture_dir
        shutil.move(str(capture_dir), str(removed_captures_dir / capture_dir.name))

    def update_tree_cache_info(self, process_id: int, classname: str) -> None:
        self.redis.hset('tree_cache', f'{process_id}|{classname}', str(self._captures_index.lru_cache_status()))

    def clear_tree_cache(self) -> None:
        self._captures_index.lru_cache_clear()

    def get_recent_captures(self, /, *, since: datetime | str | float | None=None,
                            before: datetime | float | str | None=None) -> list[str]:
        '''Get the captures that were done between two dates

        :param since: the oldest date to get captures from, None will start from the oldest capture
        :param before: the newest date to get captures from, None will end on the newest capture
        '''
        if not since:
            since = '-Inf'
        elif isinstance(since, datetime):
            since = since.timestamp()

        if not before:
            before = '+Inf'
        elif isinstance(before, datetime):
            before = before.timestamp()
        return self.redis.zrevrangebyscore('recent_captures', before, since)

    def sorted_capture_cache(self, capture_uuids: Iterable[str] | None=None,
                             cached_captures_only: bool=True,
                             index_cut_time: datetime | None=None) -> list[CaptureCache]:
        '''Get all the captures in the cache, sorted by timestamp (new -> old).
        By default, this method will only return the captures that are currently cached.'''
        # Make sure we do not try to load archived captures that would still be in 'lookup_dirs'
        cut_time = (datetime.now() - timedelta(days=get_config('generic', 'archive') - 1))
        if index_cut_time:
            if index_cut_time < cut_time:
                index_cut_time = cut_time
        else:
            index_cut_time = cut_time

        if capture_uuids is None:
            capture_uuids = self.get_recent_captures(since=index_cut_time)
            # NOTE: we absolutely have to respect the cached_captures_only setting and
            #       never overwrite it. This method is called to display the index
            #       and if we try to display everything, including the non-cached entries,
            #       the index can get stuck building a lot of captures
            # cached_captures_only = False

        if not capture_uuids:
            # No captures at all on the instance
            return []

        if cached_captures_only:
            # Do not try to build pickles
            capture_uuids = set(capture_uuids) & self._captures_index.cached_captures

        all_cache: list[CaptureCache] = [self._captures_index[uuid] for uuid in capture_uuids
                                         if self.capture_cache(uuid)
                                         and hasattr(self._captures_index[uuid], 'timestamp')]
        all_cache.sort(key=operator.attrgetter('timestamp'), reverse=True)
        return all_cache

    def capture_ready_to_store(self, capture_uuid: str, /) -> bool:
        lacus_status: CaptureStatusCore | CaptureStatusPy
        try:
            if isinstance(self.lacus, dict):
                for lacus in self.lacus.values():
                    lacus_status = lacus.get_capture_status(capture_uuid)
                    if lacus_status != CaptureStatusPy.UNKNOWN:
                        return lacus_status == CaptureStatusPy.DONE
            elif isinstance(self.lacus, PyLacus):
                lacus_status = self.lacus.get_capture_status(capture_uuid)
                return lacus_status == CaptureStatusPy.DONE
            else:
                lacus_status = self.lacus.get_capture_status(capture_uuid)
                return lacus_status == CaptureStatusCore.DONE
        except LacusUnreachable as e:
            self.logger.warning(f'Unable to connect to lacus: {e}')
            raise e
        except Exception as e:
            self.logger.warning(f'Unable to get the status for {capture_uuid} from lacus: {e}')
        return False

    def _get_lacus_capture_status(self, capture_uuid: str, /) -> CaptureStatusCore | CaptureStatusPy:
        lacus_status: CaptureStatusCore | CaptureStatusPy = CaptureStatusPy.UNKNOWN
        try:
            if isinstance(self.lacus, dict):
                for lacus in self.lacus.values():
                    lacus_status = lacus.get_capture_status(capture_uuid)
                    if lacus_status != CaptureStatusPy.UNKNOWN:
                        break
            elif isinstance(self.lacus, PyLacus):
                lacus_status = self.lacus.get_capture_status(capture_uuid)
            else:
                # Use lacuscore directly
                lacus_status = self.lacus.get_capture_status(capture_uuid)
        except LacusUnreachable as e:
            self.logger.warning(f'Unable to connect to lacus: {e}')
            raise e
        except Exception as e:
            self.logger.warning(f'Unable to get the status for {capture_uuid} from lacus: {e}')
        return lacus_status

    def get_capture_status(self, capture_uuid: str, /) -> CaptureStatusCore | CaptureStatusPy:
        '''Returns the status (queued, ongoing, done, or UUID unknown)'''
        if self.redis.hexists('lookup_dirs', capture_uuid) or self.redis.hexists('lookup_dirs_archived', capture_uuid):
            return CaptureStatusCore.DONE
        elif self.redis.sismember('ongoing', capture_uuid):
            # Post-processing on lookyloo's side
            return CaptureStatusCore.ONGOING

        lacus_status = self._get_lacus_capture_status(capture_uuid)
        if (lacus_status in [CaptureStatusCore.UNKNOWN, CaptureStatusPy.UNKNOWN]
                and self.redis.zscore('to_capture', capture_uuid) is not None):
            # Lacus doesn't know it, but it is in to_capture. Happens if we check before it's picked up by Lacus.
            return CaptureStatusCore.QUEUED
        elif lacus_status in [CaptureStatusCore.DONE, CaptureStatusPy.DONE]:
            # Done on lacus side, but not processed by Lookyloo yet (it would be in lookup_dirs)
            return CaptureStatusCore.ONGOING
        return lacus_status

    def capture_cache(self, capture_uuid: str, /, *, force_update: bool = False) -> CaptureCache | None:
        """Get the cache from redis, rebuild the tree if the internal UUID changed => slow"""
        try:
            cache = self._captures_index[capture_uuid]
            if cache and force_update:
                needs_update = False
                if not cache.user_agent and not cache.error:
                    # 2022-12-07: New cache format, store the user agent and referers.
                    needs_update = True
                if not hasattr(cache, 'title') or not cache.title:
                    # 2023-17-27: The title should *always* be there,
                    # unless the HAR file is missing or broken
                    needs_update = True
                if needs_update:
                    self._captures_index.reload_cache(capture_uuid)
                    cache = self._captures_index[capture_uuid]
            return cache
        except NoValidHarFile:
            self.logger.debug('No HAR files, {capture_uuid} is a broken capture.')
            return None
        except MissingCaptureDirectory as e:
            # The UUID is in the captures but the directory is not on the disk.
            self.logger.warning(f'Missing Directory: {e}')
            return None
        except MissingUUID:
            if self.get_capture_status(capture_uuid) not in [CaptureStatusCore.QUEUED, CaptureStatusCore.ONGOING]:
                self.logger.info(f'Unable to find {capture_uuid} (not in the cache and/or missing capture directory).')
            return None
        except LookylooException as e:
            self.logger.warning(f'Lookyloo Exception: {e}')
            return None
        except Exception as e:
            self.logger.exception(e)
            return None

    def get_crawled_tree(self, capture_uuid: str, /) -> CrawledTree:
        '''Get the generated tree in ETE Toolkit format.
        Loads the pickle if it exists, creates it otherwise.'''
        try:
            return self._captures_index[capture_uuid].tree
        except TreeNeedsRebuild:
            self._captures_index.reload_cache(capture_uuid)
            return self._captures_index[capture_uuid].tree

    def _apply_user_config(self, query: CaptureSettings, user_config: dict[str, Any]) -> CaptureSettings:
        def recursive_merge(dict1: dict[str, Any], dict2: dict[str, Any]) -> dict[str, Any]:
            # dict2 overwrites dict1
            for key, value in dict2.items():
                if key in dict1 and isinstance(dict1[key], dict) and isinstance(value, dict):
                    # Recursively merge nested dictionaries
                    dict1[key] = recursive_merge(dict1[key], value)
                else:
                    # Merge non-dictionary values
                    dict1[key] = value
            return dict1

        # merge
        if user_config.get('overwrite'):
            # config from file takes priority
            return CaptureSettings(**recursive_merge(query.model_dump(), user_config))
        else:
            return CaptureSettings(**recursive_merge(user_config, query.model_dump()))

    def enqueue_capture(self, query: CaptureSettings, source: str, user: str, authenticated: bool) -> str:
        '''Enqueue a query in the capture queue (used by the UI and the API for asynchronous processing)'''

        def get_priority(source: str, user: str, authenticated: bool) -> int:
            src_prio: int = self._priority['sources'][source] if source in self._priority['sources'] else -1
            if not authenticated:
                usr_prio = self._priority['users']['_default_anon']
                # reduce priority for anonymous users making lots of captures
                queue_size = self.redis.zscore('queues', f'{source}|{authenticated}|{user}')
                if queue_size is None:
                    queue_size = 0
                usr_prio -= int(queue_size / 10)
            else:
                usr_prio = self._priority['users'][user] if self._priority['users'].get(user) else self._priority['users']['_default_auth']
            return src_prio + usr_prio

        # NOTE: Make sure we have a useragent
        if not query.user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            self.user_agents.user_agents  # triggers an update of the default UAs
        if not query.device_name and not query.user_agent:
            query.user_agent = self.user_agents.default['useragent']

        # merge DNT into headers
        if query.dnt:
            if query.headers is None:
                query.headers = {}
            query.headers['dnt'] = query.dnt
        if authenticated:
            if user_config := load_user_config(user):
                try:
                    query = self._apply_user_config(query, user_config)
                except CaptureSettingsError as e:
                    self.logger.critical(f'Unable to apply user config for {user}: {e}')
                    raise e

        priority = get_priority(source, user, authenticated)
        if priority < -100:
            # Someone is probably abusing the system with useless URLs, remove them from the index
            query.listing = False

        if not self.headed_allowed or query.headless is None:
            # Shouldn't be needed, but just in case, force headless
            query.headless = True

        lacus: LacusCore | PyLacus
        if isinstance(self.lacus, dict):
            # Multiple remote lacus enabled, we need a name to identify the lacus
            if query.remote_lacus_name is None:
                query.remote_lacus_name = get_config('generic', 'multiple_remote_lacus').get('default')
            lacus = self.lacus[query.remote_lacus_name]
        else:
            lacus = self.lacus
        try:
            perma_uuid = lacus.enqueue(
                url=query.url,
                document_name=query.document_name,
                document=query.document,
                # depth=query.depth,
                browser=query.browser,
                device_name=query.device_name,
                user_agent=query.user_agent,
                proxy=self.global_proxy if self.global_proxy else query.proxy,
                general_timeout_in_sec=query.general_timeout_in_sec,
                cookies=query.cookies,
                storage=query.storage,
                headers=query.headers,
                http_credentials=query.http_credentials,
                viewport=query.viewport,
                referer=query.referer,
                timezone_id=query.timezone_id,
                locale=query.locale,
                geolocation=query.geolocation,
                color_scheme=query.color_scheme,
                rendered_hostname_only=query.rendered_hostname_only,
                with_favicon=query.with_favicon,
                with_trusted_timestamps=query.with_trusted_timestamps,
                allow_tracking=query.allow_tracking,
                java_script_enabled=query.java_script_enabled,
                headless=query.headless,
                init_script=query.init_script,
                uuid=query.uuid,
                # force=query.force,
                # recapture_interval=query.recapture_interval,
                priority=priority
            )
        except Exception as e:
            self.logger.critical(f'Unable to enqueue capture: {e}')
            if query.uuid:
                perma_uuid = query.uuid
            else:
                perma_uuid = str(uuid4())
            query.not_queued = True
        finally:
            if not self.redis.hexists('lookup_dirs', perma_uuid):  # already captured
                p = self.redis.pipeline()
                p.zadd('to_capture', {perma_uuid: priority})
                p.hset(perma_uuid, mapping=query.redis_dump())
                p.zincrby('queues', 1, f'{source}|{authenticated}|{user}')
                p.set(f'{perma_uuid}_mgmt', f'{source}|{authenticated}|{user}')
                p.execute()

        return perma_uuid

    def takedown_details(self, hostnode: HostNode) -> dict[str, Any]:
        if not self.uwhois.available:
            self.logger.warning('UWhois module not enabled, unable to use this method')
            raise LookylooException('UWhois module not enabled, unable to use this method')
        to_return = {'hostname': hostnode.name,
                     'contacts': self.uwhois.whois(hostnode.name, contact_email_only=True),  # List of emails from whois
                     'ips': {},  # ip: [list of contacts from whois]
                     'asns': {},  # ASN: [list of contacts from whois]
                     'all_emails': set()
                     }

        if to_return['contacts']:
            to_return['all_emails'] |= set(to_return['contacts'])

        if hasattr(hostnode, 'resolved_ips'):
            to_return['ips'] = {ip: self.uwhois.whois(ip, contact_email_only=True) for ip in set(hostnode.resolved_ips['v4']) | set(hostnode.resolved_ips['v6'])}
        else:
            self.logger.warning(f'No resolved IPs for {hostnode.name}')

        if hasattr(hostnode, 'ipasn'):
            to_return['asns'] = {asn['asn']: self.uwhois.whois(f'AS{asn["asn"]}', contact_email_only=True) for asn in hostnode.ipasn.values()}
        else:
            self.logger.warning(f'No IPASN for {hostnode.name}')

        # try to get contact from security.txt file
        try:
            txtfile = self.securitytxt.get(hostnode.name)
            parsed = self.securitytxt.parse(txtfile)
            to_return['securitytxt'] = parsed
            if 'contact' in parsed:
                if isinstance(parsed['contact'], str):
                    to_return['all_emails'].add(parsed['contact'].lstrip('mailto:'))
                else:
                    to_return['all_emails'] |= {contact.lstrip('mailto:') for contact in parsed['contact'] if contact.startswith('mailto:')}
        except SecurityTXTNotAvailable as e:
            self.logger.debug(f'Unable to get a security.txt file: {e}')

        for emails in to_return['ips'].values():
            to_return['all_emails'] |= set(emails)

        for emails in to_return['asns'].values():
            to_return['all_emails'] |= set(emails)

        # URLs specific details

        # # IPFS
        for url in hostnode.urls:
            for h in url.response['headers']:
                if h['name'].lower().startswith('x-ipfs'):
                    # got an ipfs thing
                    to_return['all_emails'].add('abuse@ipfs.io')
                    if 'urls' not in to_return:
                        to_return['urls'] = {'ipfs': {}}
                    if url.name not in to_return['urls']['ipfs']:
                        to_return['urls']['ipfs'][url.name] = ['abuse@ipfs.io']
                    else:
                        to_return['urls']['ipfs'][url.name].append('abuse@ipfs.io')
                    break

        to_return['all_emails'] = list(to_return['all_emails'])
        return to_return

    def takedown_filtered(self, hostnode: HostNode) -> set[str] | None:
        ignore_domains, ignore_emails, replace_list = load_takedown_filters()
        # checking if domain should be ignored
        pattern = r"(https?://)?(www\d?\.)?(?P<domain>[\w\.-]+\.\w+)(/\S*)?"
        if match := re.match(pattern, hostnode.name):
            # NOTE: the name may not be a hostname if the capture is not a URL.
            if re.search(ignore_domains, match.group("domain")):
                self.logger.debug(f'{hostnode.name} is ignored')
                return None
        else:
            # The name is not a domain, we won't have any contacts.
            self.logger.debug(f'{hostnode.name} is not a domain, no contacts.')
            return None

        result = self.takedown_details(hostnode)
        # process mails
        final_mails: set[str] = set()
        for mail in result['all_emails']:
            if re.search(ignore_emails, mail):
                self.logger.debug(f'{mail} is ignored')
                continue
            if mail in replace_list:
                final_mails |= set(replace_list[mail])
            else:
                final_mails.add(mail)
        return final_mails

    def contacts_filtered(self, capture_uuid: str, /) -> set[str]:
        capture = self.get_crawled_tree(capture_uuid)
        rendered_hostnode = self.get_hostnode_from_tree(capture_uuid, capture.root_hartree.rendered_node.hostnode_uuid)
        result: set[str] = set()
        for node in reversed(rendered_hostnode.get_ancestors()):
            if mails := self.takedown_filtered(node):
                result |= mails
        if mails := self.takedown_filtered(rendered_hostnode):
            result |= mails
        return result

    def contacts(self, capture_uuid: str, /) -> list[dict[str, Any]]:
        capture = self.get_crawled_tree(capture_uuid)
        rendered_hostnode = self.get_hostnode_from_tree(capture_uuid, capture.root_hartree.rendered_node.hostnode_uuid)
        result = []
        for node in reversed(rendered_hostnode.get_ancestors()):
            result.append(self.takedown_details(node))
        result.append(self.takedown_details(rendered_hostnode))
        return result

    def modules_filtered(self, capture_uuid: str, /) -> str | None:
        response = self.get_modules_responses(capture_uuid)
        if not response:
            return None
        modules = set()
        if 'vt' in response:
            vt = response.pop('vt')
            for url, report in vt.items():
                if not report:
                    continue
                for vendor, result in report['attributes']['last_analysis_results'].items():
                    if result['category'] == 'malicious':
                        modules.add(vendor)

        if 'pi' in response:
            pi = response.pop('pi')
            for url, full_report in pi.items():
                if not full_report:
                    continue
                modules.add('Phishing Initiative')

        if 'phishtank' in response:
            pt = response.pop('phishtank')
            for url, full_report in pt['urls'].items():
                if not full_report:
                    continue
                modules.add('Phishtank')

        if 'urlhaus' in response:
            uh = response.pop('urlhaus')
            for url, results in uh['urls'].items():
                if results:
                    modules.add('URLhaus')

        if 'urlscan' in response and response.get('urlscan'):
            urlscan = response.pop('urlscan')
            if 'error' not in urlscan['submission']:
                if urlscan['submission'] and urlscan['submission'].get('result'):
                    if urlscan['result']:
                        if (urlscan['result'].get('verdicts')
                                and urlscan['result']['verdicts'].get('overall')):
                            if urlscan['result']['verdicts']['overall'].get('malicious'):
                                modules.add('urlscan')
                else:
                    # unable to run the query, probably an invalid key
                    pass
        if len(modules) == 0:
            return "URL captured doesn't appear in malicious databases."

        return f"Malicious capture according to {len(modules)} module(s): {', '.join(modules)}"

    def already_sent_mail(self, capture_uuid: str, /, uuid_only: bool=True) -> bool:
        '''Check if a mail was already sent for a specific capture.
        The check is either done on the UUID only, or on the chain of redirects (if any).
        In that second case, we take the chain of redirects, keep only the hostnames,
        aggregate them if the same one is there multiple times in a row (redirect http -> https),
        and concatenate the remaining ones.
        True if the mail was already sent in the last 24h, False otherwise.
        '''
        if uuid_only:
            return bool(self.redis.exists(f'sent_mail|{capture_uuid}'))
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return False
        if hasattr(cache, 'redirects') and cache.redirects:
            hostnames = [h for h, l in itertools.groupby(urlparse(redirect).hostname for redirect in cache.redirects if urlparse(redirect).hostname) if h is not None]
            return bool(self.redis.exists(f'sent_mail|{"|".join(hostnames)}'))
        return False

    def set_sent_mail_key(self, capture_uuid: str, /, deduplicate_interval: int) -> None:
        '''Set the key for the sent mail in redis'''
        self.redis.set(f'sent_mail|{capture_uuid}', 1, ex=deduplicate_interval)
        cache = self.capture_cache(capture_uuid)
        if cache and hasattr(cache, 'redirects') and cache.redirects:
            hostnames = [h for h, l in itertools.groupby(urlparse(redirect).hostname for redirect in cache.redirects if urlparse(redirect).hostname) if h is not None]
            self.redis.set(f'sent_mail|{"|".join(hostnames)}', 1, ex=deduplicate_interval)

    def send_mail(self, capture_uuid: str, /, as_admin: bool, email: str | None=None, comment: str | None=None) -> bool | dict[str, Any]:
        '''Send an email notification regarding a specific capture'''
        if not get_config('generic', 'enable_mail_notification'):
            return {"error": "Unable to send mail: mail notification disabled"}

        email_config = get_config('generic', 'email')
        if email_deduplicate := email_config.get('deduplicate'):
            if email_deduplicate.get('uuid') and self.already_sent_mail(capture_uuid, uuid_only=True):
                return {"error": "Mail already sent (same UUID)"}
            if email_deduplicate.get('hostnames') and self.already_sent_mail(capture_uuid, uuid_only=False):
                return {"error": "Mail already sent (same redirect chain)"}
            deduplicate_interval = email_deduplicate.get('interval_in_sec')
        else:
            deduplicate_interval = 0

        smtp_auth = get_config('generic', 'email_smtp_auth')
        redirects = ''
        initial_url = ''
        misp = ''
        if cache := self.capture_cache(capture_uuid):
            if hasattr(cache, 'url'):
                if email_config['defang_urls']:
                    initial_url = defang(cache.url, colon=True, all_dots=True)
                else:
                    initial_url = cache.url
            else:
                initial_url = 'Unable to get URL from cache, this is probably a bug.'
                if hasattr(cache, 'error') and cache.error:
                    initial_url += f' - {cache.error}'

            if hasattr(cache, 'redirects') and cache.redirects:
                redirects = "Redirects:\n"
                if email_config['defang_urls']:
                    redirects += defang('\n'.join(cache.redirects), colon=True, all_dots=True)
                else:
                    redirects += '\n'.join(cache.redirects)
            else:
                redirects = "No redirects."

            if not self.misps.available:
                self.logger.info('There are no MISP instances available for a lookup.')
            else:
                for instance_name in self.misps.keys():
                    if occurrences := self.get_misp_occurrences(capture_uuid,
                                                                as_admin=as_admin,
                                                                instance_name=instance_name):
                        elements, misp_url = occurrences
                        for event_id, attributes in elements.items():
                            for value, ts in attributes:
                                if value == cache.url:
                                    now = datetime.now(timezone.utc)
                                    diff = now - ts
                                    if diff.days < 1:  # MISP event should not be older than 24hours
                                        misp += f"\n{ts.isoformat()} : {misp_url}events/{event_id}"
                                    break  # some events have more than just one timestamp, we just take the first one
        modules = self.modules_filtered(capture_uuid)
        msg = EmailMessage()
        msg['From'] = email_config['from']
        if email:
            msg['Reply-To'] = email
        msg['To'] = email_config['to']
        msg['Subject'] = email_config['subject']
        body = get_email_template()
        body = body.format(
            recipient=msg['To'].addresses[0].display_name,
            modules=modules if modules else '',
            domain=self.public_domain,
            uuid=capture_uuid,
            initial_url=initial_url,
            redirects=redirects,
            comment=comment if comment else '',
            misp=f"MISP occurrences from the last 24h: {misp}" if misp else '',
            sender=msg['From'].addresses[0].display_name,
        )
        msg.set_content(body)
        try:
            contact_for_takedown = self.contacts(capture_uuid)
            msg.add_attachment(json.dumps(contact_for_takedown, indent=2), filename='contacts.json')
        except Exception as e:
            self.logger.warning(f'Unable to get the contacts: {e}')
        try:
            with smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port']) as s:
                if smtp_auth['auth']:
                    if smtp_auth['smtp_use_starttls']:
                        if smtp_auth['verify_certificate'] is False:
                            ssl_context = ssl.create_default_context()
                            ssl_context.check_hostname = False
                            ssl_context.verify_mode = ssl.CERT_NONE
                            s.starttls(context=ssl_context)
                        else:
                            s.starttls()
                    s.login(smtp_auth['smtp_user'], smtp_auth['smtp_pass'])
                s.send_message(msg)
                if deduplicate_interval:
                    self.set_sent_mail_key(capture_uuid, deduplicate_interval)
        except Exception as e:
            self.logger.exception(e)
            self.logger.warning(msg.as_string())
            return {"error": "Unable to send mail"}
        return True

    def _load_tt_file(self, capture_uuid: str, /) -> dict[str, bytes] | None:
        tt_file = self._captures_index[capture_uuid].capture_dir / '0.trusted_timestamps.json'
        if not tt_file.exists():
            return None

        with tt_file.open() as f:
            return {name: b64decode(tst) for name, tst in json.load(f).items()}

    def get_trusted_timestamp(self, capture_uuid: str, /, name: str) -> bytes | None:
        if trusted_timestamps := self._load_tt_file(capture_uuid):
            return trusted_timestamps.get(name)
        return None

    def _prepare_tsr_data(self, capture_uuid: str, /) -> tuple[dict[str, tuple[TimeStampResponse, bytes]], cryptography.x509.Certificate] | dict[str, str]:

        def find_certificate(info: tuple[TimeStampResponse, bytes]) -> cryptography.x509.Certificate | None:
            tsr, data = info

            with open(certifi.where(), "rb") as f:
                try:
                    cert_authorities = x509.load_pem_x509_certificates(f.read())
                except Exception as e:
                    self.logger.warning(f'Unable to read file {f}: {e}')

            for certificate in cert_authorities:
                verifier = VerifierBuilder().add_root_certificate(certificate).build()
                try:
                    verifier.verify_message(tsr, data)
                    return certificate
                except VerificationError:
                    continue
            else:
                # unable to find certificate
                return None

        trusted_timestamps = self._load_tt_file(capture_uuid)
        if not trusted_timestamps:
            return {'warning': "No trusted timestamps in the capture."}

        certificate: cryptography.x509.Certificate | None = None
        to_check: dict[str, tuple[TimeStampResponse, bytes]] = {}
        success: bool
        data: str | bytes | BytesIO | None
        for tsr_name, tst in trusted_timestamps.items():
            # turn the base64 encoded blobs back to bytes and TimeStampResponse for validation
            tsr = decode_timestamp_response(tst)
            if tsr_name == 'last_redirected_url':
                data = self.get_last_url_in_address_bar(capture_uuid)
                if data:
                    to_check[tsr_name] = (tsr, data.encode())
                    if certificate is None:
                        certificate = find_certificate(to_check[tsr_name])
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            elif tsr_name == 'har':
                success, data = self.get_har(capture_uuid)
                if success:
                    to_check[tsr_name] = (tsr, gzip.decompress(data.getvalue()))
                    if certificate is None:
                        certificate = find_certificate(to_check[tsr_name])
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            elif tsr_name == 'storage':
                success, data = self.get_storage_state(capture_uuid)
                if success:
                    to_check[tsr_name] = (tsr, data.getvalue())
                    if certificate is None:
                        certificate = find_certificate(to_check[tsr_name])
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            elif tsr_name == 'html':
                success, data = self.get_html(capture_uuid)
                if success:
                    to_check[tsr_name] = (tsr, data.getvalue())
                    if certificate is None:
                        certificate = find_certificate(to_check[tsr_name])
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            elif tsr_name == 'png':
                success, data = self.get_screenshot(capture_uuid)
                if success:
                    to_check[tsr_name] = (tsr, data.getvalue())
                    if certificate is None:
                        certificate = find_certificate(to_check[tsr_name])
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            elif tsr_name in ['downloaded_filename', 'downloaded_file']:
                # get those two in one call
                if to_check.get('downloaded_filename') or to_check.get('downloaded_file'):
                    continue
                success, filename, data = self.get_data(capture_uuid)
                if success:
                    to_check['downloaded_filename'] = (tsr, filename.encode())
                    to_check['downloaded_file'] = (tsr, data.getvalue())
                else:
                    self.logger.warning(f'[{capture_uuid}] Unable to get {tsr_name} for trusted timestamp validation.')
            else:
                self.logger.warning(f'[{capture_uuid}] Unexpected entry in trusted timestamps: {tsr_name}')
                continue

        if not certificate:
            self.logger.warning(f'[{capture_uuid}] Unable to find certificate, cannot validate trusted timestamps.')
            return {'warning': 'Unable to find certificate, cannot validate trusted timestamps.'}
        return to_check, certificate

    def check_trusted_timestamps(self, capture_uuid: str, /) -> tuple[dict[str, datetime | str], str] | dict[str, str]:
        tsr_data = self._prepare_tsr_data(capture_uuid)
        if isinstance(tsr_data, dict):
            return tsr_data

        to_check, certificate = tsr_data

        verifier = VerifierBuilder().add_root_certificate(certificate).build()
        to_return: dict[str, datetime | str] = {}
        for tsr_name, entry in to_check.items():
            tsr, data = entry
            try:
                verifier.verify_message(tsr, data)
                to_return[tsr_name] = tsr.tst_info.gen_time
            except VerificationError as e:
                self.logger.warning(f'Unable to validate {tsr_name} : {e}')
                to_return[tsr_name] = 'Unable to validate: {e}'
        return to_return, b64encode(certificate.public_bytes(Encoding.DER)).decode()

    def bundle_all_trusted_timestamps(self, capture_uuid: str, /) -> BytesIO | dict[str, str]:
        tsr_data = self._prepare_tsr_data(capture_uuid)
        if isinstance(tsr_data, dict):
            return tsr_data

        to_check, certificate = tsr_data
        to_return = BytesIO()
        validator_bash = ''
        with ZipFile(to_return, 'w', compression=ZIP_DEFLATED) as z:
            z.writestr('certificate.der', certificate.public_bytes(Encoding.DER))
            for tsr_name, entry in to_check.items():
                tsr, data = entry
                z.writestr(f'{tsr_name}.tsr', tsr.as_bytes())
                z.writestr(f'{tsr_name}.data', data)
                validator_bash += f"openssl ts -CApath /etc/ssl/certs/ -verify -in {tsr_name}.tsr -data {tsr_name}.data\n"
                validator_bash += f"openssl ts -reply -in {tsr_name}.tsr -text\n"
                validator_bash += "-------------------------------------------------\n\n"
            z.writestr('validator.sh', validator_bash)
        to_return.seek(0)
        return to_return

    def _get_raw(self, capture_uuid: str, /, extension: str='*', all_files: bool=True) -> tuple[bool, BytesIO]:
        '''Get file(s) from the capture directory'''
        try:
            capture_dir = self._captures_index[capture_uuid].capture_dir
        except NoValidHarFile:
            return False, BytesIO(f'Capture {capture_uuid} has no HAR entries, which means it is broken.'.encode())
        except MissingUUID:
            return False, BytesIO(f'Capture {capture_uuid} not unavailable, try again later.'.encode())
        except MissingCaptureDirectory:
            return False, BytesIO(f'No capture {capture_uuid} on the system (directory missing).'.encode())
        all_paths = sorted(list(capture_dir.glob(f'*.{extension}')))
        if not all_files:
            # Only get the first one in the list
            if not all_paths:
                return False, BytesIO()
            with open(all_paths[0], 'rb') as f:
                return True, BytesIO(f.read())
        to_return = BytesIO()
        # Add uuid file to the export, allows to keep the same UUID across platforms.
        # NOTE: the UUID file will always be added, as long as all_files is True,
        #       even if we pass an extension
        all_paths.append(capture_dir / 'uuid')
        with ZipFile(to_return, 'w', compression=ZIP_DEFLATED) as myzip:
            for path in all_paths:
                if 'pickle' in path.name:
                    # We do not want to export the pickle
                    continue
                myzip.write(path, arcname=f'{capture_dir.name}/{path.name}')
        to_return.seek(0)
        return True, to_return

    @overload
    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: Literal[False], for_datauri: Literal[True]) -> tuple[str, str]:
        ...

    @overload
    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: Literal[True], for_datauri: Literal[False]) -> tuple[bool, BytesIO]:
        ...

    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: bool=False, for_datauri: bool=False) -> tuple[bool, BytesIO] | tuple[str, str]:
        '''Get rendered HTML'''
        # NOTE: we sometimes have multiple favicons, and sometimes,
        #       the first entry in the list is not actually a favicon. So we
        #       iterate until we find one (or fail to, but at least we tried)
        if not all_favicons and for_datauri:
            favicons_paths = sorted(list(self._captures_index[capture_uuid].capture_dir.glob('*.potential_favicons.ico')))
            if not favicons_paths:
                self.logger.debug(f'No potential favicon found for {capture_uuid}.')
                return '', ''
            for favicon_path in favicons_paths:
                with favicon_path.open('rb') as f:
                    favicon = f.read()
                if not favicon:
                    continue
                try:
                    mimetype = from_string(favicon, mime=True)
                    return mimetype, base64.b64encode(favicon).decode()
                except PureError:
                    self.logger.info(f'Unable to get the mimetype of the favicon for {capture_uuid}.')
                    continue
            else:
                self.logger.info(f'No valid favicon found for {capture_uuid}.')
                return '', ''
        return self._get_raw(capture_uuid, 'potential_favicons.ico', all_favicons)

    def get_html(self, capture_uuid: str, /, all_html: bool=False) -> tuple[bool, BytesIO]:
        '''Get rendered HTML'''
        return self._get_raw(capture_uuid, 'html', all_html)

    def get_har(self, capture_uuid: str, /, all_har: bool=False) -> tuple[bool, BytesIO]:
        '''Get rendered HAR'''
        return self._get_raw(capture_uuid, 'har.gz', all_har)

    def get_data(self, capture_uuid: str, /, *, index_in_zip: int | None=None) -> tuple[bool, str, BytesIO]:
        '''Get the data'''

        def _get_downloaded_file_by_id_from_zip(data: BytesIO, index_in_zip: int) -> tuple[bool, str, BytesIO]:
            '''Get the a downloaded file by hash.
            This method is only used if the capture downloaded multiple files'''
            with ZipFile(data) as downloaded_files:
                files_info = downloaded_files.infolist()
                if index_in_zip > len(files_info):
                    self.logger.warning(f'[{capture_uuid}] Unable to get the file {index_in_zip} from the zip file (only {len(files_info)} entries).')
                    return False, 'Invalid index in zip', BytesIO()
                with downloaded_files.open(files_info[index_in_zip]) as f:
                    return True, files_info[index_in_zip].filename, BytesIO(f.read())

        success, data_filename = self._get_raw(capture_uuid, 'data.filename', False)
        if success:
            filename = data_filename.getvalue().decode().strip()
            success, data = self._get_raw(capture_uuid, 'data', False)
            if success:
                if filename == f'{capture_uuid}_multiple_downloads.zip' and index_in_zip is not None:
                    # We have a zip file with multiple files in it
                    success, filename, data = _get_downloaded_file_by_id_from_zip(data, index_in_zip)
                    if success:
                        # We found the file in the zip
                        return True, filename, data
                return True, filename, data
            return False, filename, data
        return False, 'Unable to get the file name', BytesIO()

    def get_cookies(self, capture_uuid: str, /, all_cookies: bool=False) -> tuple[bool, BytesIO]:
        '''Get the cookie(s)'''
        return self._get_raw(capture_uuid, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_uuid: str, /) -> tuple[bool, BytesIO]:
        '''Get the screenshot(s) of the rendered page'''
        return self._get_raw(capture_uuid, 'png', all_files=False)

    def get_storage_state(self, capture_uuid: str, /) -> tuple[bool, BytesIO]:
        '''Get the storage state of the capture'''
        return self._get_raw(capture_uuid, 'storage.json', all_files=False)

    def get_last_url_in_address_bar(self, capture_uuid: str, /) -> str | None:
        '''Get the URL in the address bar at the end of the capture'''
        success, file = self._get_raw(capture_uuid, 'last_redirect.txt', all_files=False)
        if success:
            return unquote_plus(file.getvalue().decode().strip())
        return None

    def get_screenshot_thumbnail(self, capture_uuid: str, /, for_datauri: bool=False, width: int=64) -> str | BytesIO:
        '''Get the thumbnail of the rendered page. Always crop to a square.'''
        to_return = BytesIO()
        size = width, width
        try:
            success, s = self.get_screenshot(capture_uuid)
            if success:
                orig_screenshot = Image.open(s)
                to_thumbnail = orig_screenshot.crop((0, 0, orig_screenshot.width, orig_screenshot.width))
            else:
                to_thumbnail = get_error_screenshot()
        except Image.DecompressionBombError as e:
            # The image is most probably too big: https://pillow.readthedocs.io/en/stable/reference/Image.html
            self.logger.warning(f'Unable to generate the screenshot thumbnail of {capture_uuid}: image too big ({e}).')
            to_thumbnail = get_error_screenshot()
        except UnidentifiedImageError as e:
            # We might have a direct download link, and no screenshot. Assign the thumbnail accordingly.
            try:
                success, filename, data = self.get_data(capture_uuid)
                if success:
                    self.logger.debug(f'{capture_uuid} is is a download link, set thumbnail.')
                    error_img: Path = get_homedir() / 'website' / 'web' / 'static' / 'download.png'
                    to_thumbnail = Image.open(error_img)
                else:
                    # Unable to get data, probably a broken capture.
                    to_thumbnail = get_error_screenshot()
            except Exception:
                # The capture probably doesn't have a screenshot at all, no need to log that as a warning.
                self.logger.debug(f'Unable to generate the screenshot thumbnail of {capture_uuid}: {e}.')
            to_thumbnail = get_error_screenshot()

        to_thumbnail.thumbnail(size)
        to_thumbnail.save(to_return, 'png')

        to_return.seek(0)
        if for_datauri:
            return base64.b64encode(to_return.getvalue()).decode()
        else:
            return to_return

    def get_capture(self, capture_uuid: str, /) -> tuple[bool, BytesIO]:
        '''Get all the files related to this capture.'''
        return self._get_raw(capture_uuid)

    def get_urls_rendered_page(self, capture_uuid: str, /) -> list[str]:
        ct = self.get_crawled_tree(capture_uuid)
        try:
            return sorted(set(ct.root_hartree.rendered_node.urls_in_rendered_page)
                          - set(ct.root_hartree.all_url_requests.keys()))
        except Har2TreeError as e:
            self.logger.warning(f'Unable to get the rendered page for {capture_uuid}: {e}.')
            raise LookylooException("Unable to get the rendered page.")

    def compute_mmh3_shodan(self, favicon: bytes, /) -> str:
        b64 = base64.encodebytes(favicon)
        return str(mmh3.hash(b64))

    def get_ressource(self, tree_uuid: str, /, urlnode_uuid: str, h: str | None) -> tuple[str, BytesIO, str] | None:
        '''Get a specific resource from a URL node. If a hash s also given, we want an embeded resource'''

        # Break immediately if we have the hash of the empty file
        if h == 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e':
            return ('empty', BytesIO(), 'inode/x-empty')

        try:
            url = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        except IndexError:
            # unable to find the uuid, the cache is probably in a weird state.
            self.logger.info(f'Unable to find node "{urlnode_uuid}" in "{tree_uuid}"')
            return None
        except NoValidHarFile as e:
            # something went poorly when rebuilding the tree (probably a recursive error)
            self.logger.warning(e)
            return None

        if url.empty_response:
            self.logger.info(f'The response for node "{urlnode_uuid}" in "{tree_uuid}" is empty.')
            return None
        if not h or h == url.body_hash:
            # we want the body
            return url.filename if url.filename else 'file.bin', BytesIO(url.body.getvalue()), url.mimetype

        # We want an embedded ressource
        if h not in url.resources_hashes:
            self.logger.info(f'Unable to find "{h}" in capture "{tree_uuid}" - node "{urlnode_uuid}".')
            return None
        for mimetype, blobs in url.embedded_ressources.items():
            for ressource_h, blob in blobs:
                if ressource_h == h:
                    return 'embedded_ressource.bin', BytesIO(blob.getvalue()), mimetype
        self.logger.info(f'Unable to find "{h}" in capture "{tree_uuid}" - node "{urlnode_uuid}", but in a weird way.')
        return None

    def __misp_add_vt_to_URLObject(self, obj: MISPObject) -> MISPObject | None:
        urls = obj.get_attributes_by_relation('url')
        if not urls:
            return None
        url = urls[0]
        report = self.vt.get_url_lookup(url.value)
        if not report:
            return None
        vt_obj = MISPObject('virustotal-report', standalone=False)
        vt_obj.add_attribute('first-submission', value=datetime.fromtimestamp(report['attributes']['first_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('last-submission', value=datetime.fromtimestamp(report['attributes']['last_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('permalink', value=f"https://www.virustotal.com/gui/url/{report['id']}/detection", disable_correlation=True)
        obj.add_reference(vt_obj, 'analysed-with')
        return vt_obj

    def __misp_add_urlscan_to_event(self, capture_uuid: str) -> MISPAttribute | None:
        if cache := self.capture_cache(capture_uuid):
            response = self.urlscan.url_result(cache)
            if 'result' in response:
                attribute = MISPAttribute()
                attribute.value = response['result']
                attribute.type = 'link'
                return attribute
        return None

    def misp_export(self, capture_uuid: str, /, with_parent: bool=False, *, as_admin: bool=False) -> list[MISPEvent] | dict[str, str]:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': 'UUID missing in cache, try again later.'}

        # The tree is needed to generate the export. The call below makes sure it is cached
        # as it may not be if the uses calls the json export without viewing the tree first,
        # and it has been archived.
        try:
            self.get_crawled_tree(capture_uuid)
        except LookylooException as e:
            return {'error': str(e)}

        # if the file submitted on lookyloo cannot be displayed (PDF), it will be downloaded.
        # In the case, we want to have it as a FileObject in the export
        success, filename, pseudofile = self.get_data(capture_uuid)
        if success and filename:
            event = self.misps.export(cache, self.is_public_instance, filename, pseudofile)
        else:
            event = self.misps.export(cache, self.is_public_instance)
        success, screenshot = self.get_screenshot(capture_uuid)
        if success:
            misp_screenshot: MISPAttribute = event.add_attribute('attachment', 'screenshot_landing_page.png',
                                                                 data=screenshot,
                                                                 disable_correlation=True)  # type: ignore[assignment]
            misp_screenshot.first_seen = cache.timestamp
            # If the last object attached to tht event is a file, it is the rendered page
            if event.objects and event.objects[-1].name == 'file':
                event.objects[-1].add_reference(misp_screenshot, 'rendered-as', 'Screenshot of the page')

        if self.vt.available:
            response = self.vt.capture_default_trigger(cache, force=False, auto_trigger=False, as_admin=as_admin)
            if 'error' in response:
                self.logger.info(f'Unable to trigger VT: {response["error"]}')
            else:
                for e_obj in event.objects:
                    if e_obj.name != 'url':
                        continue
                    vt_obj = self.__misp_add_vt_to_URLObject(e_obj)
                    if vt_obj:
                        event.add_object(vt_obj)

        if self.phishtank.available:
            for e_obj in event.objects:
                if e_obj.name != 'url':
                    continue
                urls = e_obj.get_attributes_by_relation('url')
                if not urls:
                    continue
                pt_entry = self.phishtank.get_url_lookup(urls[0].value)
                if not pt_entry or not pt_entry.get('phish_detail_url'):
                    continue
                pt_attribute: MISPAttribute = event.add_attribute('link', value=pt_entry['phish_detail_url'], comment='Phishtank permalink')  # type: ignore[assignment]
                e_obj.add_reference(pt_attribute, 'known-as', 'Permalink on Phishtank')

        if self.urlscan.available:
            response = self.urlscan.capture_default_trigger(cache, force=False, auto_trigger=False, as_admin=as_admin)
            if 'error' in response:
                self.logger.info(f'Unable to trigger URLScan: {response["error"]}')
            else:
                urlscan_attribute = self.__misp_add_urlscan_to_event(capture_uuid)
                if urlscan_attribute:
                    event.add_attribute(**urlscan_attribute)

        if with_parent and cache.parent:
            parent = self.misp_export(cache.parent, with_parent)
            if isinstance(parent, dict):
                # Something bad happened
                return parent

            event.extends_uuid = parent[-1].uuid
            parent.append(event)
            return parent

        return [event]

    def get_misp_occurrences(self, capture_uuid: str, /, as_admin: bool,
                             *, instance_name: str | None=None) -> tuple[dict[int, set[tuple[str, datetime]]], str] | None:
        if instance_name is None:
            misp = self.misps.default_misp
        elif self.misps.get(instance_name) is not None:
            misp = self.misps[instance_name]
        else:
            self.logger.warning(f'MISP instance "{instance_name}" does not exists.')
            return None

        if not misp.available:
            return None
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_uuid}) is cached.')
            return None
        nodes_to_lookup = ct.root_hartree.rendered_node.get_ancestors() + [ct.root_hartree.rendered_node]
        to_return: dict[int, set[tuple[str, datetime]]] = defaultdict(set)
        for node in nodes_to_lookup:
            hits = misp.lookup(node, ct.root_hartree.get_host_node_by_uuid(node.hostnode_uuid), as_admin=as_admin)
            for event_id, values in hits.items():
                if not isinstance(event_id, int) or not isinstance(values, set):
                    continue
                to_return[event_id].update(values)
        return to_return, misp.client.root_url

    def get_hashes_with_context(self, tree_uuid: str, /, algorithm: str, *, urls_only: bool=False) -> dict[str, set[str]] | dict[str, list[URLNode]]:
        """Build (on demand) hashes for all the ressources of the tree, using the alorighm provided by the user.
        If you just want the hashes in SHA512, use the get_hashes method, it gives you a list of hashes an they're build
        with the tree. This method is computing the hashes when you query it, so it is slower."""
        ct = self.get_crawled_tree(tree_uuid)
        hashes = ct.root_hartree.build_all_hashes(algorithm)
        if urls_only:
            return {h: {node.name for node in nodes} for h, nodes in hashes.items()}
        return hashes

    def merge_hashlookup_tree(self, tree_uuid: str, /, as_admin: bool=False) -> tuple[dict[str, dict[str, Any]], int]:
        if not self.hashlookup.available:
            raise LookylooException('Hashlookup module not enabled.')
        cache = self.capture_cache(tree_uuid)
        if not cache:
            raise LookylooException(f'Capture {tree_uuid} not ready.')
        hashes_tree = self.get_hashes_with_context(tree_uuid, algorithm='sha1')

        hashlookup_file = cache.capture_dir / 'hashlookup.json'
        if not hashlookup_file.exists():
            self.hashlookup.capture_default_trigger(cache, force=False, auto_trigger=False, as_admin=as_admin)

        if not hashlookup_file.exists():
            # no hits on hashlookup
            return {}, len(hashes_tree)

        with hashlookup_file.open() as f:
            hashlookup_entries = json.load(f)

        to_return: dict[str, dict[str, Any]] = defaultdict(dict)

        for sha1 in hashlookup_entries.keys():
            to_return[sha1]['nodes'] = hashes_tree[sha1]
            to_return[sha1]['hashlookup'] = hashlookup_entries[sha1]
        return to_return, len(hashes_tree)

    def get_hashes(self, tree_uuid: str, /, hostnode_uuid: str | None=None, urlnode_uuid: str | None=None) -> tuple[bool, set[str]]:
        """Return hashes (sha512) of resources.
        Only tree_uuid: All the hashes
        tree_uuid and hostnode_uuid: hashes of all the resources in that hostnode (including embedded ressources)
        tree_uuid, hostnode_uuid, and urlnode_uuid: hash of the URL node body, and embedded resources
        """
        container: CrawledTree | HostNode | URLNode
        if urlnode_uuid:
            container = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        elif hostnode_uuid:
            container = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
        else:
            container = self.get_crawled_tree(tree_uuid)
        if container:
            return True, get_resources_hashes(container)
        return False, set()

    def get_ips(self, tree_uuid: str, /, hostnode_uuid: str | None=None, urlnode_uuid: str | None=None) -> set[str]:
        """Return all the unique IPs:
            * of a complete tree if no hostnode_uuid and urlnode_uuid are given
            * of a HostNode if hostnode_uuid is given
            * of a URLNode if urlnode_uuid is given
        """
        def get_node_ip(urlnode: URLNode) -> str | None:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
            if 'hostname_is_ip' in urlnode.features and urlnode.hostname_is_ip:
                ip = ipaddress.ip_address(urlnode.hostname)
            elif 'ip_address' in urlnode.features:
                ip = urlnode.ip_address

            if ip:
                return ip.compressed
            return None

        if urlnode_uuid:
            node = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
            if ip := get_node_ip(node):
                return {ip}
            return set()
        elif hostnode_uuid:
            node = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
            to_return = set()
            for urlnode in node.urls:
                if ip := get_node_ip(urlnode):
                    to_return.add(ip)
            return to_return
        else:
            ct = self.get_crawled_tree(tree_uuid)
            to_return = set()
            for urlnode in ct.root_hartree.url_tree.traverse():
                if ip := get_node_ip(urlnode):
                    to_return.add(ip)
            return to_return

    def get_hostnames(self, tree_uuid: str, /, hostnode_uuid: str | None=None, urlnode_uuid: str | None=None) -> set[str]:
        """Return all the unique hostnames:
            * of a complete tree if no hostnode_uuid and urlnode_uuid are given
            * of a HostNode if hostnode_uuid is given
            * of a URLNode if urlnode_uuid is given
        """
        if urlnode_uuid:
            node = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
            return {node.hostname}
        elif hostnode_uuid:
            node = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
            return {node.name}
        else:
            ct = self.get_crawled_tree(tree_uuid)
            return {node.name for node in ct.root_hartree.hostname_tree.traverse()}

    def get_urls(self, tree_uuid: str, /, hostnode_uuid: str | None=None, urlnode_uuid: str | None=None) -> set[str]:
        """Return all the unique URLs:
            * of a complete tree if no hostnode_uuid and urlnode_uuid are given
            * of a HostNode if hostnode_uuid is given
            * of a URLNode if urlnode_uuid is given
        """
        if urlnode_uuid:
            node = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
            return {node.name}
        elif hostnode_uuid:
            node = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
            return {urlnode.name for urlnode in node.urls}
        else:
            ct = self.get_crawled_tree(tree_uuid)
            return {node.name for node in ct.root_hartree.url_tree.traverse()}

    def get_playwright_devices(self) -> dict[str, Any]:
        """Get the preconfigured devices from Playwright"""
        return get_devices()

    def get_stats(self) -> dict[str, list[Any]]:
        '''Gather statistics about the lookyloo instance'''
        today = date.today()
        calendar_week = today.isocalendar()[1]

        stats_dict = {'submissions': 0, 'redirects': 0}
        stats: dict[int, dict[int, dict[str, Any]]] = {}
        weeks_stats: dict[int, dict[str, Any]] = {}

        # Only recent captures that are not archived
        for cache in self.sorted_capture_cache():
            if not hasattr(cache, 'timestamp'):
                continue
            date_submission: datetime = cache.timestamp

            if date_submission.year not in stats:
                stats[date_submission.year] = {}
            if date_submission.month not in stats[date_submission.year]:
                stats[date_submission.year][date_submission.month] = defaultdict(dict, **stats_dict)
                stats[date_submission.year][date_submission.month]['uniq_urls'] = set()
            stats[date_submission.year][date_submission.month]['submissions'] += 1
            stats[date_submission.year][date_submission.month]['uniq_urls'].add(cache.url)
            if hasattr(cache, 'redirects') and len(cache.redirects) > 0:
                stats[date_submission.year][date_submission.month]['redirects'] += len(cache.redirects)
                stats[date_submission.year][date_submission.month]['uniq_urls'].update(cache.redirects)

            if ((date_submission.year == today.year and calendar_week - 1 <= date_submission.isocalendar()[1] <= calendar_week)
                    or (calendar_week == 1 and date_submission.year == today.year - 1 and date_submission.isocalendar()[1] in [52, 53])):
                if date_submission.isocalendar()[1] not in weeks_stats:
                    weeks_stats[date_submission.isocalendar()[1]] = defaultdict(dict, **stats_dict)
                    weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'] = set()
                weeks_stats[date_submission.isocalendar()[1]]['submissions'] += 1
                weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'].add(cache.url)
                if hasattr(cache, 'redirects') and len(cache.redirects) > 0:
                    weeks_stats[date_submission.isocalendar()[1]]['redirects'] += len(cache.redirects)
                    weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'].update(cache.redirects)

        # Build limited stats based on archved captures and the indexes
        for _, capture_path in self.redis.hscan_iter('lookup_dirs_archived'):
            capture_ts = datetime.fromisoformat(capture_path.rsplit('/', 1)[-1])
            if capture_ts.year not in stats:
                stats[capture_ts.year] = {}
            if capture_ts.month not in stats[capture_ts.year]:
                stats[capture_ts.year][capture_ts.month] = {'submissions': 0}
            stats[capture_ts.year][capture_ts.month]['submissions'] += 1

        statistics: dict[str, list[Any]] = {'weeks': [], 'years': []}
        for week_number in sorted(weeks_stats.keys()):
            week_stat = weeks_stats[week_number]
            urls = week_stat.pop('uniq_urls')
            week_stat['week_number'] = week_number
            week_stat['uniq_urls'] = len(urls)
            week_stat['uniq_domains'] = len(uniq_domains(urls))
            statistics['weeks'].append(week_stat)

        for year in sorted(stats.keys()):
            year_stats: dict[str, int | list[Any]] = {'year': year, 'months': [], 'yearly_submissions': 0}
            for month in sorted(stats[year].keys()):
                month_stats = stats[year][month]
                if len(month_stats) == 1:
                    # archived captures, missing many values
                    month_stats['month_number'] = month
                else:
                    urls = month_stats.pop('uniq_urls')
                    month_stats['month_number'] = month
                    month_stats['uniq_urls'] = len(urls)
                    month_stats['uniq_domains'] = len(uniq_domains(urls))

                year_stats['months'].append(month_stats)  # type: ignore[union-attr]
                year_stats['yearly_submissions'] += month_stats['submissions']
            statistics['years'].append(year_stats)

        return statistics

    def unpack_full_capture_archive(self, archive: BytesIO, listing: bool) -> tuple[str, dict[str, list[str]]]:
        unrecoverable_error = False
        messages: dict[str, list[str]] = {'errors': [], 'warnings': []}
        os: str | None = None
        browser: str | None = None
        parent: str | None = None
        downloaded_filename: str | None = None
        downloaded_file: bytes | None = None
        error: str | None = None
        har: dict[str, Any] | None = None
        screenshot: bytes | None = None
        html: str | None = None
        last_redirected_url: str | None = None
        cookies: Cookies | list[dict[str, str]] | None = None
        storage: StorageState | None = None
        capture_settings: CaptureSettings | None = None
        potential_favicons: set[bytes] | None = None
        trusted_timestamps: dict[str, str] | None = None

        files_to_skip = ['cnames.json', 'ipasn.json', 'ips.json', 'mx.json',
                         'nameservers.json', 'soa.json', 'hashlookup.json']

        with ZipFile(archive, 'r') as lookyloo_capture:
            potential_favicons = set()
            for filename in lookyloo_capture.namelist():
                if filename.endswith('0.har.gz'):
                    # new formal
                    har = json.loads(gzip.decompress(lookyloo_capture.read(filename)))
                elif filename.endswith('0.har'):
                    # old format
                    har = json.loads(lookyloo_capture.read(filename))
                elif filename.endswith('0.html'):
                    html = lookyloo_capture.read(filename).decode()
                elif filename.endswith('0.last_redirect.txt'):
                    last_redirected_url = lookyloo_capture.read(filename).decode()
                elif filename.endswith('0.png'):
                    screenshot = lookyloo_capture.read(filename)
                elif filename.endswith('0.cookies.json'):
                    # Not required
                    cookies = json.loads(lookyloo_capture.read(filename))
                elif filename.endswith('0.storage.json'):
                    # Not required
                    storage = json.loads(lookyloo_capture.read(filename))
                elif filename.endswith('potential_favicons.ico'):
                    # We may have more than one favicon
                    potential_favicons.add(lookyloo_capture.read(filename))
                elif filename.endswith('uuid'):
                    uuid = lookyloo_capture.read(filename).decode()
                    if self._captures_index.uuid_exists(uuid):
                        messages['warnings'].append(f'UUID {uuid} already exists, set a new one.')
                        uuid = str(uuid4())
                elif filename.endswith('meta'):
                    meta = json.loads(lookyloo_capture.read(filename))
                    if 'os' in meta:
                        os = meta['os']
                    if 'browser' in meta:
                        browser = meta['browser']
                elif filename.endswith('no_index'):
                    # Force it to false regardless the form
                    listing = False
                elif filename.endswith('parent'):
                    parent = lookyloo_capture.read(filename).decode()
                elif filename.endswith('0.data.filename'):
                    downloaded_filename = lookyloo_capture.read(filename).decode()
                elif filename.endswith('0.data'):
                    downloaded_file = lookyloo_capture.read(filename)
                elif filename.endswith('error.txt'):
                    error = lookyloo_capture.read(filename).decode()
                elif filename.endswith('0.trusted_timestamps.json'):
                    trusted_timestamps = json.loads(lookyloo_capture.read(filename).decode())
                elif filename.endswith('capture_settings.json'):
                    _capture_settings = json.loads(lookyloo_capture.read(filename))
                    try:
                        capture_settings = CaptureSettings(**_capture_settings)
                    except CaptureSettingsError as e:
                        unrecoverable_error = True
                        messages['errors'].append(f'Invalid Capture Settings: {e}')
                else:
                    for to_skip in files_to_skip:
                        if filename.endswith(to_skip):
                            break
                    else:
                        messages['warnings'].append(f'Unexpected file in the capture archive: {filename}')
            if not har or not html or not last_redirected_url or not screenshot:
                # If we don't have these 4 files, the archive is incomplete and we should not store it.
                unrecoverable_error = True
                if not har:
                    messages['errors'].append('Invalid submission: missing HAR file')
                if not html:
                    messages['errors'].append('Invalid submission: missing HTML file')
                if not last_redirected_url:
                    messages['errors'].append('Invalid submission: missing landing page')
                if not screenshot:
                    messages['errors'].append('Invalid submission: missing screenshot')

            if unrecoverable_error:
                return '', messages

            self.store_capture(uuid, is_public=listing,
                               os=os, browser=browser, parent=parent,
                               downloaded_filename=downloaded_filename, downloaded_file=downloaded_file,
                               error=error, har=har, png=screenshot, html=html,
                               last_redirected_url=last_redirected_url,
                               cookies=cookies, storage=storage,
                               capture_settings=capture_settings if capture_settings else None,
                               potential_favicons=potential_favicons,
                               trusted_timestamps=trusted_timestamps if trusted_timestamps else None)
            return uuid, messages

    def store_capture(self, uuid: str, is_public: bool,
                      os: str | None=None, browser: str | None=None,
                      parent: str | None=None,
                      downloaded_filename: str | None=None, downloaded_file: bytes | None=None,
                      error: str | None=None, har: dict[str, Any] | None=None,
                      png: bytes | None=None, html: str | None=None,
                      last_redirected_url: str | None=None,
                      cookies: Cookies | list[dict[str, str]] | None=None,
                      storage: StorageState | dict[str, Any] | None=None,
                      capture_settings: CaptureSettings | None=None,
                      potential_favicons: set[bytes] | None=None,
                      trusted_timestamps: dict[str, str] | None=None,
                      auto_report: bool | dict[str, str] | None = None
                      ) -> Path:

        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / f'{now.day:02}' / now.isoformat()
        safe_create_dir(dirpath)

        if os or browser:
            meta: dict[str, str] = {}
            if os:
                meta['os'] = os
            if browser:
                meta['browser'] = browser
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(uuid)

        # Write no_index marker (optional)
        if not is_public:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if parent:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(parent)

        if downloaded_filename:
            with (dirpath / '0.data.filename').open('w') as _downloaded_filename:
                _downloaded_filename.write(downloaded_filename)

        if downloaded_file:
            with (dirpath / '0.data').open('wb') as _downloaded_file:
                _downloaded_file.write(downloaded_file)

        if error:
            with (dirpath / 'error.txt').open('w') as _error:
                json.dump(error, _error)

        if har:
            with gzip.open(dirpath / '0.har.gz', 'wt') as f_out:
                f_out.write(json.dumps(har))

        if png:
            with (dirpath / '0.png').open('wb') as _img:
                _img.write(png)

        if html:
            try:
                with (dirpath / '0.html').open('w') as _html:
                    _html.write(html)
            except UnicodeEncodeError:
                # NOTE: Unable to store as string, try to store as bytes instead
                #        Yes, it is dirty.
                with (dirpath / '0.html').open('wb') as _html:
                    _html.write(html.encode('utf-16', 'surrogatepass'))

        if last_redirected_url:
            with (dirpath / '0.last_redirect.txt').open('w') as _redir:
                _redir.write(last_redirected_url)

        if cookies:
            with (dirpath / '0.cookies.json').open('w') as _cookies:
                json.dump(cookies, _cookies)

        if storage:
            with (dirpath / '0.storage.json').open('w') as _storage:
                json.dump(storage, _storage)

        if capture_settings:
            with (dirpath / 'capture_settings.json').open('w') as _cs:
                _cs.write(capture_settings.model_dump_json(indent=2, exclude_none=True))

        if potential_favicons:
            for f_id, favicon in enumerate(potential_favicons):
                with (dirpath / f'{f_id}.potential_favicons.ico').open('wb') as _fw:
                    _fw.write(favicon)

        if trusted_timestamps:
            with (dirpath / '0.trusted_timestamps.json').open('w') as _tt:
                json.dump(trusted_timestamps, _tt)

        if auto_report:
            # autoreport needs to be triggered once the tree is build
            if isinstance(auto_report, bool):
                (dirpath / 'auto_report').touch()
            else:
                with (dirpath / 'auto_report').open('w') as _ar:
                    json.dump(auto_report, _ar)

        self.redis.hset('lookup_dirs', uuid, str(dirpath))
        self.redis.zadd('recent_captures', {uuid: now.timestamp()})
        return dirpath
