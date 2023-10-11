#!/usr/bin/env python3

import base64
import copy
import gzip
import json
import logging
import operator
import smtplib
import ssl
import time

from collections import defaultdict
from datetime import date, datetime, timezone
from email.message import EmailMessage
from functools import cached_property
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union, TYPE_CHECKING, overload, Literal
from urllib.parse import urlparse
from uuid import uuid4
from zipfile import ZipFile

from defang import defang  # type: ignore
from har2tree import CrawledTree, HostNode, URLNode
from lacuscore import (LacusCore,
                       CaptureStatus as CaptureStatusCore,
                       # CaptureResponse as CaptureResponseCore)
                       # CaptureResponseJson as CaptureResponseJsonCore,
                       CaptureSettings as CaptureSettingsCore)
from PIL import Image, UnidentifiedImageError
from playwrightcapture import get_devices
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

from .capturecache import CaptureCache, CapturesIndex
from .context import Context
from .default import LookylooException, get_homedir, get_config, get_socket_path, safe_create_dir
from .exceptions import (MissingCaptureDirectory,
                         MissingUUID, TreeNeedsRebuild, NoValidHarFile)
from .helpers import (get_captures_dir, get_email_template,
                      get_resources_hashes, get_taxonomies,
                      uniq_domains, ParsedUserAgent, load_cookies, UserAgents,
                      get_useragent_for_requests)
from .indexing import Indexing
from .modules import (MISPs, PhishingInitiative, UniversalWhois,
                      UrlScan, VirusTotal, Phishtank, Hashlookup,
                      RiskIQ, RiskIQError, Pandora, URLhaus)

if TYPE_CHECKING:
    from playwright.async_api import Cookie


class CaptureSettings(CaptureSettingsCore, total=False):
    '''The capture settings that can be passed to Lookyloo'''
    listing: Optional[int]
    not_queued: Optional[int]
    auto_report: Optional[Union[str, Dict[str, str]]]
    dnt: Optional[str]
    browser_name: Optional[str]
    os: Optional[str]
    parent: Optional[str]


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.indexing = Indexing()
        self.user_agents = UserAgents()
        self.is_public_instance = get_config('generic', 'public_instance')
        self.public_domain = get_config('generic', 'public_domain')

        self.global_proxy = {}
        if global_proxy := get_config('generic', 'global_proxy'):
            if global_proxy.get('enable'):
                self.global_proxy = copy.copy(global_proxy)
                self.global_proxy.pop('enable')

        self.securitytxt = PySecurityTXT(useragent=get_useragent_for_requests())
        self.taxonomies = get_taxonomies()

        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('cache'), decode_responses=True)
        self.capture_dir: Path = get_captures_dir()

        self._priority = get_config('generic', 'priority')

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
        self.riskiq = RiskIQ(config_name='RiskIQ')
        self.pandora = Pandora(config_name='Pandora')
        self.urlhaus = URLhaus(config_name='URLhaus')

        self.monitoring_enabled = False
        if monitoring_config := get_config('generic', 'monitoring'):
            if monitoring_config['enable']:
                self.monitoring = PyLookylooMonitoring(monitoring_config['url'], get_useragent_for_requests())
                if self.monitoring.is_up:
                    self.monitoring_enabled = True
                    # NOTE: maybe move that somewhere else: we'll need to restart the webserver
                    # if we change the settings in the monitoring instance
                    self.monitoring_settings = self.monitoring.instance_settings()

        self.logger.info('Initializing context...')
        self.context = Context()
        self.logger.info('Context initialized.')
        self.logger.info('Initializing index...')
        self._captures_index = CapturesIndex(self.redis, self.context)
        self.logger.info('Index initialized.')

        # init lacus
        self.lacus

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    @cached_property
    def lacus(self):
        has_remote_lacus = False
        self._lacus: Union[PyLacus, LacusCore]
        if get_config('generic', 'remote_lacus'):
            remote_lacus_config = get_config('generic', 'remote_lacus')
            if remote_lacus_config.get('enable'):
                self.logger.info("Remote lacus enabled, trying to set it up...")
                lacus_retries = 10
                while lacus_retries > 0:
                    remote_lacus_url = remote_lacus_config.get('url')
                    self._lacus = PyLacus(remote_lacus_url)
                    if self._lacus.is_up:
                        has_remote_lacus = True
                        self.logger.info(f"Remote lacus enabled to {remote_lacus_url}.")
                        break
                    lacus_retries -= 1
                    self.logger.warning(f"Unable to setup remote lacus to {remote_lacus_url}, trying again {lacus_retries} more time(s).")
                    time.sleep(10)
                else:
                    raise LookylooException('Remote lacus is enabled but unreachable.')

        if not has_remote_lacus:
            # We need a redis connector that doesn't decode.
            redis: Redis = Redis(unix_socket_path=get_socket_path('cache'))
            self._lacus = LacusCore(redis, tor_proxy=get_config('generic', 'tor_proxy'),
                                    max_capture_time=get_config('generic', 'max_capture_time'),
                                    only_global_lookups=get_config('generic', 'only_global_lookups'),
                                    loglevel=get_config('generic', 'loglevel'))
        return self._lacus

    def add_context(self, capture_uuid: str, /, urlnode_uuid: str, *, ressource_hash: str,
                    legitimate: bool, malicious: bool, details: Dict[str, Dict[str, str]]):
        '''Adds context information to a capture or a URL node'''
        if malicious:
            self.context.add_malicious(ressource_hash, details['malicious'])
        if legitimate:
            self.context.add_legitimate(ressource_hash, details['legitimate'])

    def add_to_legitimate(self, capture_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None):
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

    def get_hostnode_from_tree(self, capture_uuid: str, /, node_uuid: str) -> HostNode:
        '''Get a host node from a tree, by UUID'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_statistics(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get the statistics of a capture.'''
        ct = self.get_crawled_tree(capture_uuid)
        return ct.root_hartree.stats

    def get_info(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get basic information about the capture.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': f'Unable to find UUID {capture_uuid} in the cache.'}

        if not hasattr(cache, 'uuid'):
            self.logger.critical(f'Cache for {capture_uuid} is broken: {cache}.')
            return {'error': f'Sorry, the capture {capture_uuid} is broken, please report it to the admin.'}

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
        return to_return

    def get_meta(self, capture_uuid: str, /) -> Dict[str, str]:
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

    def get_capture_settings(self, capture_uuid: str, /) -> CaptureSettings:
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {}
        cs_file = cache.capture_dir / 'capture_settings.json'
        if cs_file.exists():
            with cs_file.open('r') as f:
                return json.load(f)
        return {}

    def categories_capture(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get all the categories related to a capture, in MISP Taxonomies format'''
        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = [line.strip() for line in f.readlines()]
            return {e: self.taxonomies.revert_machinetag(e) for e in current_categories}
        return {}

    def categorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Add a category (MISP Taxonomy tag) to a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        # Make sure the category is mappable to a taxonomy.
        self.taxonomies.revert_machinetag(category)

        categ_file = self._captures_index[capture_uuid].capture_dir / 'categories'
        # get existing categories if possible
        if categ_file.exists():
            with categ_file.open() as f:
                current_categories = {line.strip() for line in f.readlines()}
        else:
            current_categories = set()
        current_categories.add(category)
        with categ_file.open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

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
        current_categories.remove(category)
        with categ_file.open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

    def trigger_modules(self, capture_uuid: str, /, force: bool=False, auto_trigger: bool=False) -> Dict:
        '''Launch the 3rd party modules on a capture.
        It uses the cached result *if* the module was triggered the same day.
        The `force` flag re-triggers the module regardless of the cache.'''
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_uuid}) is cached.')
            return {'error': f'UUID {capture_uuid} is either unknown or the tree is not ready yet.'}

        self.uwhois.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        self.hashlookup.capture_default_trigger(ct, auto_trigger=auto_trigger)

        to_return: Dict[str, Dict] = {'PhishingInitiative': {}, 'VirusTotal': {}, 'UrlScan': {},
                                      'URLhaus': {}}
        if cache := self.capture_cache(capture_uuid):
            to_return['PhishingInitiative'] = self.pi.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger)
            to_return['VirusTotal'] = self.vt.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger)
            to_return['UrlScan'] = self.urlscan.capture_default_trigger(
                cache,
                visibility='unlisted' if (cache and cache.no_index) else 'public',
                force=force, auto_trigger=auto_trigger)
            to_return['Phishtank'] = self.phishtank.capture_default_trigger(cache, auto_trigger=auto_trigger)
            to_return['URLhaus'] = self.urlhaus.capture_default_trigger(cache, auto_trigger=auto_trigger)
        return to_return

    def get_modules_responses(self, capture_uuid: str, /) -> Optional[Dict[str, Any]]:
        '''Get the responses of the modules from the cached responses on the disk'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            self.logger.warning(f'Unable to get the modules responses unless the capture {capture_uuid} is cached')
            return None
        if not hasattr(cache, 'url'):
            self.logger.warning(f'The capture {capture_uuid} does not have a URL in the cache, it is broken.')
            return None

        to_return: Dict[str, Any] = {}
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

    def get_historical_lookups(self, capture_uuid: str, /, force: bool=False) -> Dict:
        # this method is only trigered when the user wants to get more details about the capture
        # by looking at Passive DNS systems, check if there are hits in the current capture
        # in another one and things like that. The trigger_modules method is for getting
        # information about the current status of the capture in other systems.
        cache = self.capture_cache(capture_uuid)
        if not cache:
            self.logger.warning(f'Unable to get the modules responses unless the capture {capture_uuid} is cached')
            return {}
        to_return: Dict[str, Any] = {}
        if self.riskiq.available:
            try:
                self.riskiq.capture_default_trigger(cache)
                if hasattr(cache, 'redirects') and cache.redirects:
                    hostname = urlparse(cache.redirects[-1]).hostname
                else:
                    hostname = urlparse(cache.url).hostname
                if hostname:
                    to_return['riskiq'] = self.riskiq.get_passivedns(hostname)
            except RiskIQError as e:
                self.logger.warning(e.response.content)
        return to_return

    def hide_capture(self, capture_uuid: str, /) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self._captures_index[capture_uuid].capture_dir
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()
        self._captures_index.reload_cache(capture_uuid)

    def update_tree_cache_info(self, process_id: int, classname: str) -> None:
        self.redis.hset('tree_cache', f'{process_id}|{classname}', str(self._captures_index.lru_cache_status()))

    def sorted_capture_cache(self, capture_uuids: Optional[Iterable[str]]=None, cached_captures_only: bool=True, index_cut_time: Optional[datetime]=None) -> List[CaptureCache]:
        '''Get all the captures in the cache, sorted by timestamp (new -> old).
        By default, this method will only return the captures that are currently cached.'''
        if capture_uuids is None:
            all_captures = {k: v for k, v in sorted(self.redis.hgetall('lookup_dirs').items(), key=lambda item: item[1], reverse=True)}
            if index_cut_time is None:
                capture_uuids = list(all_captures.keys())
            else:
                capture_uuids = []
                for uuid, directory in self.redis.hgetall('lookup_dirs').items():
                    date_str = directory.rsplit('/', 1)[1]
                    if datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc) < index_cut_time:
                        continue
                    capture_uuids.append(uuid)
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

        all_cache: List[CaptureCache] = [self._captures_index[uuid] for uuid in capture_uuids
                                         if self.capture_cache(uuid)
                                         and hasattr(self._captures_index[uuid], 'timestamp')]
        all_cache.sort(key=operator.attrgetter('timestamp'), reverse=True)
        return all_cache

    def get_capture_status(self, capture_uuid: str, /) -> Union[CaptureStatusCore, CaptureStatusPy]:
        '''Returns the status (queued, ongoing, done, or UUID unknown)'''
        if self.redis.hexists('lookup_dirs', capture_uuid):
            return CaptureStatusCore.DONE
        elif self.redis.sismember('ongoing', capture_uuid):
            # Post-processing on lookyloo's side
            return CaptureStatusCore.ONGOING
        try:
            lacus_status = self.lacus.get_capture_status(capture_uuid)
        except Exception as e:
            self.logger.warning(f'Unable to get the status for {capture_uuid} from lacus: {e}')
            if self.redis.zscore('to_capture', capture_uuid) is not None:
                return CaptureStatusCore.QUEUED
            else:
                return CaptureStatusCore.UNKNOWN

        if (lacus_status == CaptureStatusCore.UNKNOWN
                and self.redis.zscore('to_capture', capture_uuid) is not None):
            # If we do the query before lacus picks it up, we will tell to the user that the UUID doesn't exists.
            return CaptureStatusCore.QUEUED
        elif lacus_status == CaptureStatusCore.DONE:
            # Done on lacus side, but not processed by Lookyloo yet (it would be in lookup_dirs)
            return CaptureStatusCore.ONGOING
        return lacus_status

    def capture_cache(self, capture_uuid: str, /, *, force_update: bool = False) -> Optional[CaptureCache]:
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

    def _prepare_lacus_query(self, query: CaptureSettings) -> CaptureSettings:
        # Remove the none, it makes redis unhappy
        query = {k: v for k, v in query.items() if v is not None}  # type: ignore

        if 'url' in query and query['url'] is not None:
            # Make sure the URL does not have any space or newline
            query['url'] = query['url'].strip()

        # NOTE: Lookyloo' capture can pass a do not track header independently from the default headers, merging it here
        headers = query.pop('headers', {})
        if 'dnt' in query:
            if isinstance(headers, str):
                headers += f'\nDNT: {query.pop("dnt")}'
                headers = headers.strip()
            elif isinstance(headers, dict):
                dnt_entry = query.pop("dnt")
                if dnt_entry:
                    headers['DNT'] = dnt_entry.strip()

        if headers:
            query['headers'] = headers

        # NOTE: Lookyloo can get the cookies in somewhat weird formats, mornalizing them
        query['cookies'] = load_cookies(query.pop('cookies', None))

        # NOTE: Make sure we have a useragent
        user_agent = query.pop('user_agent', None)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            self.user_agents.user_agents  # triggers an update of the default UAs
        if 'device_name' not in query:
            query['user_agent'] = user_agent if user_agent else self.user_agents.default['useragent']

        # NOTE: the document must be base64 encoded
        document: Optional[Union[str, bytes]] = query.pop('document', None)
        if document:
            if isinstance(document, bytes):
                query['document'] = base64.b64encode(document).decode()
            else:
                query['document'] = document
        return query

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

        for key, value in query.items():
            if isinstance(value, bool):
                query[key] = 1 if value else 0  # type: ignore
            elif isinstance(value, (list, dict)):
                query[key] = json.dumps(value) if value else None  # type: ignore

        query = self._prepare_lacus_query(query)

        priority = get_priority(source, user, authenticated)
        query['priority'] = priority
        if priority < -100:
            # Someone is probably abusing the system with useless URLs, remove them from the index
            query['listing'] = 0
        try:
            perma_uuid = self.lacus.enqueue(
                url=query.get('url', None),
                document_name=query.get('document_name', None),
                document=query.get('document', None),
                # depth=query.get('depth', 0),
                browser=query.get('browser', None),
                device_name=query.get('device_name', None),
                user_agent=query.get('user_agent', None),
                proxy=self.global_proxy if self.global_proxy else query.get('proxy', None),
                general_timeout_in_sec=query.get('general_timeout_in_sec', None),
                cookies=query.get('cookies', None),
                headers=query.get('headers', None),
                http_credentials=query.get('http_credentials', None),
                viewport=query.get('viewport', None),
                referer=query.get('referer', None),
                timezone_id=query.get('timezone_id', None),
                locale=query.get('locale', None),
                geolocation=query.get('geolocation', None),
                color_scheme=query.get('color_scheme', None),
                rendered_hostname_only=query.get('rendered_hostname_only', True),
                with_favicon=query.get('with_favicon', True),
                # force=query.get('force', False),
                # recapture_interval=query.get('recapture_interval', 300),
                priority=query.get('priority', 0)
            )
        except Exception as e:
            self.logger.critical(f'Unable to enqueue capture: {e}')
            perma_uuid = str(uuid4())
            query['not_queued'] = 1
        finally:
            if (not self.redis.hexists('lookup_dirs', perma_uuid)  # already captured
                    and self.redis.zscore('to_capture', perma_uuid) is None):  # capture ongoing

                # Make the settings redis compatible
                mapping_capture: Dict[str, Union[bytes, float, int, str]] = {}
                for key, value in query.items():
                    if isinstance(value, bool):
                        mapping_capture[key] = 1 if value else 0
                    elif isinstance(value, (list, dict)):
                        if value:
                            mapping_capture[key] = json.dumps(value)
                    elif value is not None:
                        mapping_capture[key] = value  # type: ignore

                p = self.redis.pipeline()
                p.zadd('to_capture', {perma_uuid: query['priority']})
                p.hset(perma_uuid, mapping=mapping_capture)
                p.zincrby('queues', 1, f'{source}|{authenticated}|{user}')
                p.set(f'{perma_uuid}_mgmt', f'{source}|{authenticated}|{user}')
                p.execute()

        return perma_uuid

    def takedown_details(self, hostnode: HostNode) -> Dict[str, Any]:
        if not self.uwhois.available:
            self.logger.warning('UWhois module not enabled, unable to use this method')
            raise LookylooException('UWhois module not enabled, unable to use this method')
        to_return = {'hostname': hostnode.name,
                     'contacts': self.uwhois.whois(hostnode.name, contact_email_only=True),  # List of emails from whois
                     'ips': {},  # ip: [list of contacts from whois]
                     'asns': {},  # ASN: [list of contacts from whois]
                     'all_emails': set()
                     }
        to_return['ips'] = {ip: self.uwhois.whois(ip, contact_email_only=True) for ip in hostnode.resolved_ips['v4'] | hostnode.resolved_ips['v6']}
        to_return['asns'] = {asn['asn']: self.uwhois.whois(f'AS{asn["asn"]}', contact_email_only=True) for asn in hostnode.ipasn.values()}

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

    def contacts(self, capture_uuid: str, /) -> List[Dict[str, Any]]:
        capture = self.get_crawled_tree(capture_uuid)
        rendered_hostnode = self.get_hostnode_from_tree(capture_uuid, capture.root_hartree.rendered_node.hostnode_uuid)
        result = []
        for node in reversed(rendered_hostnode.get_ancestors()):
            result.append(self.takedown_details(node))
        result.append(self.takedown_details(rendered_hostnode))
        return result

    def send_mail(self, capture_uuid: str, /, email: str='', comment: Optional[str]=None) -> None:
        '''Send an email notification regarding a specific capture'''
        if not get_config('generic', 'enable_mail_notification'):
            return

        email_config = get_config('generic', 'email')
        smtp_auth = get_config('generic', 'email_smtp_auth')
        redirects = ''
        initial_url = ''
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

        msg = EmailMessage()
        msg['From'] = email_config['from']
        if email:
            msg['Reply-To'] = email
        msg['To'] = email_config['to']
        msg['Subject'] = email_config['subject']
        body = get_email_template()
        body = body.format(
            recipient=msg['To'].addresses[0].display_name,
            domain=self.public_domain,
            uuid=capture_uuid,
            initial_url=initial_url,
            redirects=redirects,
            comment=comment if comment else '',
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
        except Exception as e:
            self.logger.exception(e)
            self.logger.warning(msg.as_string())

    def _get_raw(self, capture_uuid: str, /, extension: str='*', all_files: bool=True) -> BytesIO:
        '''Get file(s) from the capture directory'''
        try:
            capture_dir = self._captures_index[capture_uuid].capture_dir
        except NoValidHarFile:
            return BytesIO(f'Capture {capture_uuid} has no HAR entries, which means it is broken.'.encode())
        except MissingUUID:
            return BytesIO(f'Capture {capture_uuid} not unavailable, try again later.'.encode())
        except MissingCaptureDirectory:
            return BytesIO(f'No capture {capture_uuid} on the system (directory missing).'.encode())
        all_paths = sorted(list(capture_dir.glob(f'*.{extension}')))
        if not all_files:
            # Only get the first one in the list
            if not all_paths:
                return BytesIO()
            with open(all_paths[0], 'rb') as f:
                return BytesIO(f.read())
        to_return = BytesIO()
        # Add uuid file to the export, allows to keep the same UUID across platforms.
        # NOTE: the UUID file will always be added, as long as all_files is True,
        #       even if we pass an extension
        all_paths.append(capture_dir / 'uuid')
        with ZipFile(to_return, 'w') as myzip:
            for path in all_paths:
                if 'pickle' in path.name:
                    # We do not want to export the pickle
                    continue
                myzip.write(path, arcname=f'{capture_dir.name}/{path.name}')
        to_return.seek(0)
        return to_return

    @overload
    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: Literal[False], for_datauri: Literal[True]) -> str:
        ...

    @overload
    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: Literal[True], for_datauri: Literal[False]) -> BytesIO:
        ...

    def get_potential_favicons(self, capture_uuid: str, /, all_favicons: bool=False, for_datauri: bool=False) -> Union[BytesIO, str]:
        '''Get rendered HTML'''
        fav = self._get_raw(capture_uuid, 'potential_favicons.ico', all_favicons)
        if not all_favicons and for_datauri:
            return base64.b64encode(fav.getvalue()).decode()
        return fav

    def get_html(self, capture_uuid: str, /, all_html: bool=False) -> BytesIO:
        '''Get rendered HTML'''
        return self._get_raw(capture_uuid, 'html', all_html)

    def get_data(self, capture_uuid: str, /) -> Tuple[str, BytesIO]:
        '''Get the data'''
        return self._get_raw(capture_uuid, 'data.filename', False).getvalue().decode(), self._get_raw(capture_uuid, 'data', False)

    def get_cookies(self, capture_uuid: str, /, all_cookies: bool=False) -> BytesIO:
        '''Get the cookie(s)'''
        return self._get_raw(capture_uuid, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_uuid: str, /) -> BytesIO:
        '''Get the screenshot(s) of the rendered page'''
        return self._get_raw(capture_uuid, 'png', all_files=False)

    def get_screenshot_thumbnail(self, capture_uuid: str, /, for_datauri: bool=False, width: int=64) -> Union[str, BytesIO]:
        '''Get the thumbnail of the rendered page. Always crop to a square.'''
        to_return = BytesIO()
        size = width, width
        try:
            s = self.get_screenshot(capture_uuid)
            orig_screenshot = Image.open(s)
            to_thumbnail = orig_screenshot.crop((0, 0, orig_screenshot.width, orig_screenshot.width))
        except Image.DecompressionBombError as e:
            # The image is most probably too big: https://pillow.readthedocs.io/en/stable/reference/Image.html
            self.logger.warning(f'Unable to generate the screenshot thumbnail of {capture_uuid}: image too big ({e}).')
            error_img: Path = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
            to_thumbnail = Image.open(error_img)
        except UnidentifiedImageError as e:
            # We might have a direct download link, and no screenshot. Assign the thumbnail accordingly.
            try:
                filename, data = self.get_data(capture_uuid)
                if filename:
                    self.logger.info(f'{capture_uuid} is is a download link, set thumbnail.')
                    error_img = get_homedir() / 'website' / 'web' / 'static' / 'download.png'
                else:
                    # No screenshot and no data, it is probably because the capture failed.
                    error_img = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
            except Exception:
                # The capture probably doesn't have a screenshot at all, no need to log that as a warning.
                self.logger.debug(f'Unable to generate the screenshot thumbnail of {capture_uuid}: {e}.')
                error_img = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
            to_thumbnail = Image.open(error_img)

        to_thumbnail.thumbnail(size)
        to_thumbnail.save(to_return, 'png')

        to_return.seek(0)
        if for_datauri:
            return base64.b64encode(to_return.getvalue()).decode()
        else:
            return to_return

    def get_capture(self, capture_uuid: str, /) -> BytesIO:
        '''Get all the files related to this capture.'''
        return self._get_raw(capture_uuid)

    def get_urls_rendered_page(self, capture_uuid: str, /) -> List[str]:
        ct = self.get_crawled_tree(capture_uuid)
        return sorted(set(ct.root_hartree.rendered_node.urls_in_rendered_page)
                      - set(ct.root_hartree.all_url_requests.keys()))

    def get_body_hash_investigator(self, body_hash: str, /) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float]]]:
        '''Returns all the captures related to a hash (sha512), used in the web interface.'''
        total_captures, details = self.indexing.get_body_hash_captures(body_hash, limit=-1)
        cached_captures = self.sorted_capture_cache([d[0] for d in details])
        captures = [(cache.uuid, cache.title) for cache in cached_captures]
        domains = self.indexing.get_body_hash_domains(body_hash)
        return captures, domains

    def get_body_hash_full(self, body_hash: str, /) -> Tuple[Dict[str, List[Dict[str, str]]], BytesIO]:
        '''Returns a lot of information about the hash (sha512) and the hits in the instance.
        Also contains the data (base64 encoded)'''
        details = self.indexing.get_body_hash_urls(body_hash)

        # Break immediately if we have the hash of the empty file
        if body_hash == 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e':
            return details, BytesIO()

        # get the body from the first entry in the details list
        for _, entries in details.items():
            if not entries:
                continue
            ct = self.get_crawled_tree(entries[0]['capture'])
            try:
                urlnode = ct.root_hartree.get_url_node_by_uuid(entries[0]['urlnode'])
            except Exception:
                # Unable to find URLnode in the tree, it probably has been rebuild.
                self.logger.warning(f'Unable to find {entries[0]["urlnode"]} in entries[0]["capture"]')
                continue

            # From that point, we just try to get the content. Break as soon as we found one.
            if urlnode.body_hash == body_hash:
                # the hash we're looking for is the whole file
                return details, urlnode.body
            else:
                # The hash is an embedded resource
                for _, blobs in urlnode.embedded_ressources.items():
                    for h, b in blobs:
                        if h == body_hash:
                            return details, b

        # TODO: Couldn't find the file anywhere. Maybe return a warning in the file?
        return details, BytesIO()

    def get_all_body_hashes(self, capture_uuid: str, /) -> Dict[str, Dict[str, Union[URLNode, int]]]:
        ct = self.get_crawled_tree(capture_uuid)
        to_return: Dict[str, Dict[str, Union[URLNode, int]]] = defaultdict()
        for node in ct.root_hartree.url_tree.traverse():
            if node.empty_response or node.body_hash in to_return:
                # If we have the same hash more than once, skip
                continue
            total_captures, details = self.indexing.get_body_hash_captures(node.body_hash, limit=-1)
            # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
            to_return[node.body_hash] = {'node': node, 'total_captures': total_captures}
        return to_return

    def get_latest_url_capture(self, url: str, /) -> Optional[CaptureCache]:
        '''Get the most recent capture with this URL'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url))
        if captures:
            return captures[0]
        return None

    def get_url_occurrences(self, url: str, /, limit: int=20, cached_captures_only: bool=True) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the URL has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url), cached_captures_only=cached_captures_only)

        to_return: List[Dict] = []
        for capture in captures[:limit]:
            ct = self.get_crawled_tree(capture.uuid)
            to_append: Dict[str, Union[str, Dict]] = {'capture_uuid': capture.uuid,
                                                      'start_timestamp': capture.timestamp.isoformat(),
                                                      'title': capture.title}
            urlnodes: Dict[str, Dict[str, str]] = {}
            for urlnode in ct.root_hartree.url_tree.search_nodes(name=url):
                urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                          'hostnode_uuid': urlnode.hostnode_uuid}
                if hasattr(urlnode, 'body_hash'):
                    urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
            to_append['urlnodes'] = urlnodes
            to_return.append(to_append)
        return to_return

    def get_hostname_occurrences(self, hostname: str, /, with_urls_occurrences: bool=False, limit: int=20, cached_captures_only: bool=True) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the hostname has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_hostname(hostname), cached_captures_only=cached_captures_only)

        to_return: List[Dict] = []
        for capture in captures[:limit]:
            ct = self.get_crawled_tree(capture.uuid)
            to_append: Dict[str, Union[str, List, Dict]] = {'capture_uuid': capture.uuid,
                                                            'start_timestamp': capture.timestamp.isoformat(),
                                                            'title': capture.title}
            hostnodes: List[str] = []
            if with_urls_occurrences:
                urlnodes: Dict[str, Dict[str, str]] = {}
            for hostnode in ct.root_hartree.hostname_tree.search_nodes(name=hostname):
                hostnodes.append(hostnode.uuid)
                if with_urls_occurrences:
                    for urlnode in hostnode.urls:
                        urlnodes[urlnode.uuid] = {'start_time': urlnode.start_time.isoformat(),
                                                  'url': urlnode.name,
                                                  'hostnode_uuid': urlnode.hostnode_uuid}
                        if hasattr(urlnode, 'body_hash'):
                            urlnodes[urlnode.uuid]['hash'] = urlnode.body_hash
                to_append['hostnodes'] = hostnodes
                if with_urls_occurrences:
                    to_append['urlnodes'] = urlnodes
                to_return.append(to_append)
        return to_return

    def get_cookie_name_investigator(self, cookie_name: str, /) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float, List[Tuple[str, float]]]]]:
        '''Returns all the captures related to a cookie name entry, used in the web interface.'''
        cached_captures = self.sorted_capture_cache([entry[0] for entry in self.indexing.get_cookies_names_captures(cookie_name)])
        captures = [(cache.uuid, cache.title) for cache in cached_captures]
        domains = [(domain, freq, self.indexing.cookies_names_domains_values(cookie_name, domain))
                   for domain, freq in self.indexing.get_cookie_domains(cookie_name)]
        return captures, domains

    def get_hhh_investigator(self, hhh: str, /) -> Tuple[List[Tuple[str, str, str, str]], List[Tuple[str, str]]]:
        '''Returns all the captures related to a cookie name entry, used in the web interface.'''
        all_captures = dict(self.indexing.get_http_headers_hashes_captures(hhh))
        if cached_captures := self.sorted_capture_cache([entry for entry in all_captures]):
            captures = []
            for cache in cached_captures:
                try:
                    urlnode = self.get_urlnode_from_tree(cache.uuid, all_captures[cache.uuid])
                except Exception as e:
                    self.logger.warning(f'Cache for {cache.uuid} needs a rebuild: {e}.')
                    self._captures_index.remove_pickle(cache.uuid)
                    continue
                captures.append((cache.uuid, urlnode.hostnode_uuid, urlnode.name, cache.title))
            # get the headers and format them as they were in the response
            urlnode = self.get_urlnode_from_tree(cached_captures[0].uuid, all_captures[cached_captures[0].uuid])
            headers = [(header["name"], header["value"]) for header in urlnode.response['headers']]
            return captures, headers
        return [], []

    def hash_lookup(self, blob_hash: str, url: str, capture_uuid: str) -> Tuple[int, Dict[str, List[Tuple[str, str, str, str, str]]]]:
        '''Search all the captures a specific hash was seen.
        If a URL is given, it splits the results if the hash is seen on the same URL or an other one.
        Capture UUID avoids duplicates on the same capture'''
        captures_list: Dict[str, List[Tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
        total_captures, details = self.indexing.get_body_hash_captures(blob_hash, url, filter_capture_uuid=capture_uuid, limit=-1,
                                                                       prefered_uuids=self._captures_index.cached_captures)
        for h_capture_uuid, url_uuid, url_hostname, same_url in details:
            cache = self.capture_cache(h_capture_uuid)
            if cache and hasattr(cache, 'title'):
                if same_url:
                    captures_list['same_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
                else:
                    captures_list['different_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
        # Sort by timestamp by default
        captures_list['same_url'].sort(key=lambda y: y[3])
        captures_list['different_url'].sort(key=lambda y: y[3])
        return total_captures, captures_list

    def get_ressource(self, tree_uuid: str, /, urlnode_uuid: str, h: Optional[str]) -> Optional[Tuple[str, BytesIO, str]]:
        '''Get a specific resource from a URL node. If a hash s also given, we want an embeded resource'''
        try:
            url = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        except IndexError:
            # unable to find the uuid, the cache is probably in a weird state.
            return None
        except NoValidHarFile as e:
            # something went poorly when rebuilding the tree (probably a recursive error)
            self.logger.warning(e)
            return None
        if url.empty_response:
            return None
        if not h or h == url.body_hash:
            # we want the body
            return url.filename if url.filename else 'file.bin', BytesIO(url.body.getvalue()), url.mimetype

        # We want an embedded ressource
        if h not in url.resources_hashes:
            return None
        for mimetype, blobs in url.embedded_ressources.items():
            for ressource_h, blob in blobs:
                if ressource_h == h:
                    return 'embedded_ressource.bin', BytesIO(blob.getvalue()), mimetype
        return None

    def __misp_add_vt_to_URLObject(self, obj: MISPObject) -> Optional[MISPObject]:
        urls = obj.get_attributes_by_relation('url')
        url = urls[0]
        self.vt.url_lookup(url.value)
        report = self.vt.get_url_lookup(url.value)
        if not report:
            return None
        vt_obj = MISPObject('virustotal-report', standalone=False)
        vt_obj.add_attribute('first-submission', value=datetime.fromtimestamp(report['attributes']['first_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('last-submission', value=datetime.fromtimestamp(report['attributes']['last_submission_date']), disable_correlation=True)
        vt_obj.add_attribute('permalink', value=f"https://www.virustotal.com/gui/url/{report['id']}/detection", disable_correlation=True)
        obj.add_reference(vt_obj, 'analysed-with')
        return vt_obj

    def __misp_add_urlscan_to_event(self, capture_uuid: str, visibility: str) -> Optional[MISPAttribute]:
        if cache := self.capture_cache(capture_uuid):
            response = self.urlscan.url_submit(cache, visibility)
            if 'result' in response:
                attribute = MISPAttribute()
                attribute.value = response['result']
                attribute.type = 'link'
                return attribute
        return None

    def misp_export(self, capture_uuid: str, /, with_parent: bool=False) -> Union[List[MISPEvent], Dict[str, str]]:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': 'UUID missing in cache, try again later.'}

        # The tree is needed to generate the export. The call below makes sure it is cached
        # as it may not be if the uses calls the json export without viewing the tree first,
        # and it has been archived.
        self.get_crawled_tree(capture_uuid)

        # if the file submitted on lookyloo cannot be displayed (PDF), it will be downloaded.
        # In the case, we want to have it as a FileObject in the export
        filename, pseudofile = self.get_data(capture_uuid)
        if filename:
            event = self.misps.export(cache, self.is_public_instance, filename, pseudofile)
        else:
            event = self.misps.export(cache, self.is_public_instance)
        screenshot: MISPAttribute = event.add_attribute('attachment', 'screenshot_landing_page.png',
                                                        data=self.get_screenshot(cache.uuid),
                                                        disable_correlation=True)  # type: ignore
        # If the last object attached to tht event is a file, it is the rendered page
        if event.objects and event.objects[-1].name == 'file':
            event.objects[-1].add_reference(screenshot, 'rendered-as', 'Screenshot of the page')

        if self.vt.available:
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
                pt_attribute: MISPAttribute = event.add_attribute('link', value=pt_entry['phish_detail_url'], comment='Phishtank permalink')  # type: ignore
                e_obj.add_reference(pt_attribute, 'known-as', 'Permalink on Phishtank')

        if self.urlscan.available:
            urlscan_attribute = self.__misp_add_urlscan_to_event(
                capture_uuid,
                visibility='unlisted' if (cache and cache.no_index) else 'public')
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

    def get_misp_occurrences(self, capture_uuid: str, /, *, instance_name: Optional[str]=None) -> Optional[Tuple[Dict[str, Set[str]], str]]:
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
        to_return: Dict[str, Set[str]] = defaultdict(set)
        for node in nodes_to_lookup:
            hits = misp.lookup(node, ct.root_hartree.get_host_node_by_uuid(node.hostnode_uuid))
            for event_id, values in hits.items():
                if not isinstance(values, set):
                    continue
                to_return[event_id].update(values)
        return to_return, misp.client.root_url

    def get_hashes_with_context(self, tree_uuid: str, /, algorithm: str, *, urls_only: bool=False) -> Union[Dict[str, Set[str]], Dict[str, List[URLNode]]]:
        """Build (on demand) hashes for all the ressources of the tree, using the alorighm provided by the user.
        If you just want the hashes in SHA512, use the get_hashes method, it gives you a list of hashes an they're build
        with the tree. This method is computing the hashes when you query it, so it is slower."""
        ct = self.get_crawled_tree(tree_uuid)
        hashes = ct.root_hartree.build_all_hashes(algorithm)
        if urls_only:
            return {h: {node.name for node in nodes} for h, nodes in hashes.items()}
        return hashes

    def merge_hashlookup_tree(self, tree_uuid: str, /) -> Tuple[Dict[str, Dict[str, Any]], int]:
        if not self.hashlookup.available:
            raise LookylooException('Hashlookup module not enabled.')
        hashes_tree = self.get_hashes_with_context(tree_uuid, algorithm='sha1')

        hashlookup_file = self._captures_index[tree_uuid].capture_dir / 'hashlookup.json'
        if not hashlookup_file.exists():
            ct = self.get_crawled_tree(tree_uuid)
            self.hashlookup.capture_default_trigger(ct, auto_trigger=False)

        if not hashlookup_file.exists():
            # no hits on hashlookup
            return {}, len(hashes_tree)

        with hashlookup_file.open() as f:
            hashlookup_entries = json.load(f)

        to_return: Dict[str, Dict[str, Any]] = defaultdict(dict)

        for sha1 in hashlookup_entries.keys():
            to_return[sha1]['nodes'] = hashes_tree[sha1]
            to_return[sha1]['hashlookup'] = hashlookup_entries[sha1]
        return to_return, len(hashes_tree)

    def get_hashes(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return hashes (sha512) of resources.
        Only tree_uuid: All the hashes
        tree_uuid and hostnode_uuid: hashes of all the resources in that hostnode (including embedded ressources)
        tree_uuid, hostnode_uuid, and urlnode_uuid: hash of the URL node body, and embedded resources
        """
        container: Union[CrawledTree, HostNode, URLNode]
        if urlnode_uuid:
            container = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        elif hostnode_uuid:
            container = self.get_hostnode_from_tree(tree_uuid, hostnode_uuid)
        else:
            container = self.get_crawled_tree(tree_uuid)
        return get_resources_hashes(container)

    def get_hostnames(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
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

    def get_urls(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
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

    def get_playwright_devices(self) -> Dict:
        """Get the preconfigured devices from Playwright"""
        return get_devices()

    def get_hostnode_investigator(self, capture_uuid: str, /, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        '''Gather all the informations needed to display the Hostnode investigator popup.'''

        def normalize_known_content(h: str, /, known_content: Dict[str, Any], url: URLNode) -> Tuple[Optional[Union[str, List[Any]]], Optional[Tuple[bool, Any]]]:
            ''' There are a few different sources to figure out known vs. legitimate content,
            this method normalize it for the web interface.'''
            known: Optional[Union[str, List[Any]]] = None
            legitimate: Optional[Tuple[bool, Any]] = None
            if h not in known_content:
                return known, legitimate

            if known_content[h]['type'] in ['generic', 'sanejs']:
                known = known_content[h]['details']
            elif known_content[h]['type'] == 'legitimate_on_domain':
                legit = False
                if url.hostname in known_content[h]['details']:
                    legit = True
                legitimate = (legit, known_content[h]['details'])
            elif known_content[h]['type'] == 'malicious':
                legitimate = (False, known_content[h]['details'])

            return known, legitimate

        ct = self.get_crawled_tree(capture_uuid)
        hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)

        known_content = self.context.find_known_content(hostnode)
        self.uwhois.query_whois_hostnode(hostnode)

        urls: List[Dict[str, Any]] = []
        for url in hostnode.urls:
            # For the popup, we need:
            # * https vs http
            # * everything after the domain
            # * the full URL
            to_append: Dict[str, Any] = {
                'encrypted': url.name.startswith('https'),
                'url_path': url.name.split('/', 3)[-1],
                'url_object': url,
            }

            if not url.empty_response:
                # Index lookup
                # %%% Full body %%%
                freq = self.indexing.body_hash_fequency(url.body_hash)
                to_append['body_hash_details'] = freq
                if freq and 'hash_freq' in freq and freq['hash_freq'] and freq['hash_freq'] > 1:
                    to_append['body_hash_details']['other_captures'] = self.hash_lookup(url.body_hash, url.name, capture_uuid)

                # %%% Embedded ressources %%%
                if hasattr(url, 'embedded_ressources') and url.embedded_ressources:
                    to_append['embedded_ressources'] = {}
                    for mimetype, blobs in url.embedded_ressources.items():
                        for h, blob in blobs:
                            if h in to_append['embedded_ressources']:
                                # Skip duplicates
                                continue
                            freq_embedded = self.indexing.body_hash_fequency(h)
                            to_append['embedded_ressources'][h] = freq_embedded
                            to_append['embedded_ressources'][h]['body_size'] = blob.getbuffer().nbytes
                            to_append['embedded_ressources'][h]['type'] = mimetype
                            if freq_embedded['hash_freq'] > 1:
                                to_append['embedded_ressources'][h]['other_captures'] = self.hash_lookup(h, url.name, capture_uuid)
                    for h in to_append['embedded_ressources'].keys():
                        known, legitimate = normalize_known_content(h, known_content, url)
                        if known:
                            to_append['embedded_ressources'][h]['known_content'] = known
                        elif legitimate:
                            to_append['embedded_ressources'][h]['legitimacy'] = legitimate

                known, legitimate = normalize_known_content(url.body_hash, known_content, url)
                if known:
                    to_append['known_content'] = known
                elif legitimate:
                    to_append['legitimacy'] = legitimate

            # Optional: Cookies sent to server in request -> map to nodes who set the cookie in response
            if hasattr(url, 'cookies_sent'):
                to_display_sent: Dict[str, Set[Iterable[Optional[str]]]] = defaultdict(set)
                for cookie, contexts in url.cookies_sent.items():
                    if not contexts:
                        # Locally created?
                        to_display_sent[cookie].add(('Unknown origin', ))
                        continue
                    for context in contexts:
                        to_display_sent[cookie].add((context['setter'].hostname, context['setter'].hostnode_uuid))
                to_append['cookies_sent'] = to_display_sent

            # Optional: Cookies received from server in response -> map to nodes who send the cookie in request
            if hasattr(url, 'cookies_received'):
                to_display_received: Dict[str, Dict[str, Set[Iterable[Optional[str]]]]] = {'3rd_party': defaultdict(set), 'sent': defaultdict(set), 'not_sent': defaultdict(set)}
                for domain, c_received, is_3rd_party in url.cookies_received:
                    if c_received not in ct.root_hartree.cookies_sent:
                        # This cookie is never sent.
                        if is_3rd_party:
                            to_display_received['3rd_party'][c_received].add((domain, ))
                        else:
                            to_display_received['not_sent'][c_received].add((domain, ))
                        continue

                    for url_node in ct.root_hartree.cookies_sent[c_received]:
                        if is_3rd_party:
                            to_display_received['3rd_party'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
                        else:
                            to_display_received['sent'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
                to_append['cookies_received'] = to_display_received

            urls.append(to_append)
        return hostnode, urls

    def get_stats(self) -> Dict[str, List]:
        '''Gather statistics about the lookyloo instance'''
        today = date.today()
        calendar_week = today.isocalendar()[1]

        stats_dict = {'submissions': 0, 'submissions_with_redirects': 0, 'redirects': 0}
        stats: Dict[int, Dict[int, Dict[str, Any]]] = {}
        weeks_stats: Dict[int, Dict] = {}

        # Load the archived captures from redis
        archived: List[CaptureCache] = []
        p = self.redis.pipeline()
        for directory in self.redis.hvals('lookup_dirs_archived'):
            p.hgetall(directory)
        for cache in p.execute():
            if not cache:
                continue
            try:
                archived.append(CaptureCache(cache))
            except LookylooException as e:
                self.logger.warning(f'Unable load cache for {cache.get("uuid")} - {e}.')

        for cache in self.sorted_capture_cache() + archived:
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
                stats[date_submission.year][date_submission.month]['submissions_with_redirects'] += 1
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
                    weeks_stats[date_submission.isocalendar()[1]]['submissions_with_redirects'] += 1
                    weeks_stats[date_submission.isocalendar()[1]]['redirects'] += len(cache.redirects)
                    weeks_stats[date_submission.isocalendar()[1]]['uniq_urls'].update(cache.redirects)

        statistics: Dict[str, List] = {'weeks': [], 'years': []}
        for week_number in sorted(weeks_stats.keys()):
            week_stat = weeks_stats[week_number]
            urls = week_stat.pop('uniq_urls')
            week_stat['week_number'] = week_number
            week_stat['uniq_urls'] = len(urls)
            week_stat['uniq_domains'] = len(uniq_domains(urls))
            statistics['weeks'].append(week_stat)

        for year in sorted(stats.keys()):
            year_stats: Dict[str, Union[int, List]] = {'year': year, 'months': [], 'yearly_submissions': 0, 'yearly_redirects': 0}
            for month in sorted(stats[year].keys()):
                month_stats = stats[year][month]
                urls = month_stats.pop('uniq_urls')
                month_stats['month_number'] = month
                month_stats['uniq_urls'] = len(urls)
                month_stats['uniq_domains'] = len(uniq_domains(urls))
                year_stats['months'].append(month_stats)  # type: ignore

                year_stats['yearly_submissions'] += month_stats['submissions']
                year_stats['yearly_redirects'] += month_stats['redirects']
            statistics['years'].append(year_stats)
        return statistics

    def store_capture(self, uuid: str, is_public: bool,
                      os: Optional[str]=None, browser: Optional[str]=None,
                      parent: Optional[str]=None,
                      downloaded_filename: Optional[str]=None, downloaded_file: Optional[bytes]=None,
                      error: Optional[str]=None, har: Optional[Dict[str, Any]]=None,
                      png: Optional[bytes]=None, html: Optional[str]=None,
                      last_redirected_url: Optional[str]=None,
                      cookies: Optional[Union[List['Cookie'], List[Dict[str, str]]]]=None,
                      capture_settings: Optional[CaptureSettings]=None,
                      potential_favicons: Optional[Set[bytes]]=None
                      ) -> None:

        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / now.isoformat()
        safe_create_dir(dirpath)

        if os or browser:
            meta: Dict[str, str] = {}
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

        if capture_settings:
            with (dirpath / 'capture_settings.json').open('w') as _cs:
                json.dump(capture_settings, _cs)

        if potential_favicons:
            for f_id, favicon in enumerate(potential_favicons):
                with (dirpath / f'{f_id}.potential_favicons.ico').open('wb') as _fw:
                    _fw.write(favicon)

        self.redis.hset('lookup_dirs', uuid, str(dirpath))
