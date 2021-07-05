#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
from collections import defaultdict, Counter
from datetime import datetime, date, timedelta
from email.message import EmailMessage
from io import BufferedIOBase, BytesIO
import ipaddress
import json
import logging
from pathlib import Path
import pickle
import smtplib
import socket
import sys
from typing import Union, Dict, List, Tuple, Optional, Any, MutableMapping, Set, Iterable
from urllib.parse import urlsplit, urljoin
from uuid import uuid4
from zipfile import ZipFile
import operator
import time

from defang import refang  # type: ignore
import dns.resolver
import dns.rdatatype
from har2tree import CrawledTree, Har2TreeError, HarFile, HostNode, URLNode
from PIL import Image  # type: ignore
from pymisp import MISPEvent, MISPAttribute, MISPObject
from pymisp.tools import URLObject, FileObject
import requests
from requests.exceptions import HTTPError
from redis import Redis
from scrapysplashwrapper import crawl
from werkzeug.useragents import UserAgent

from .exceptions import NoValidHarFile, MissingUUID, LookylooException
from .helpers import (get_homedir, get_socket_path, load_cookies, get_config,
                      safe_create_dir, get_email_template, load_pickle_tree,
                      remove_pickle_tree, get_resources_hashes, get_taxonomies, uniq_domains,
                      CaptureStatus, try_make_file)
from .modules import VirusTotal, SaneJavaScript, PhishingInitiative, MISP, UniversalWhois
from .capturecache import CaptureCache
from .context import Context
from .indexing import Indexing


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.indexing = Indexing()
        self.is_public_instance = get_config('generic', 'public_instance')
        self.public_domain = get_config('generic', 'public_domain')
        self.taxonomies = get_taxonomies()

        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.capture_dir: Path = get_homedir() / 'scraped'
        if os.environ.get('SPLASH_URL_DOCKER'):
            # In order to have a working default for the docker image, it is easier to use an environment variable
            self.splash_url: str = os.environ['SPLASH_URL_DOCKER']
        else:
            self.splash_url = get_config('generic', 'splash_url')
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')

        self._priority = get_config('generic', 'priority')

        safe_create_dir(self.capture_dir)

        # Initialize 3rd party components
        self.pi = PhishingInitiative(get_config('modules', 'PhishingInitiative'))
        if not self.pi.available:
            self.logger.warning('Unable to setup the PhishingInitiative module')

        self.vt = VirusTotal(get_config('modules', 'VirusTotal'))
        if not self.vt.available:
            self.logger.warning('Unable to setup the VirusTotal module')

        self.sanejs = SaneJavaScript(get_config('modules', 'SaneJS'))
        if not self.sanejs.available:
            self.logger.warning('Unable to setup the SaneJS module')

        self.misp = MISP(get_config('modules', 'MISP'))
        if not self.misp.available:
            self.logger.warning('Unable to setup the MISP module')

        self.uwhois = UniversalWhois(get_config('modules', 'UniversalWhois'))
        if not self.uwhois.available:
            self.logger.warning('Unable to setup the UniversalWhois module')

        self.context = Context(self.sanejs)
        self._captures_index: Dict[str, CaptureCache] = {}

        if not self.redis.exists('cache_loaded'):
            self._init_existing_dumps()

    def _get_priority(self, source: str, user: str, authenticated: bool) -> int:
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

    def cache_user_agents(self, user_agent: str, remote_ip: str) -> None:
        '''Cache the useragents of the visitors'''
        today = date.today().isoformat()
        self.redis.zincrby(f'user_agents|{today}', 1, f'{remote_ip}|{user_agent}')

    def build_ua_file(self) -> None:
        '''Build a file in a format compatible with the capture page'''
        yesterday = (date.today() - timedelta(days=1))
        self_generated_ua_file_path = get_homedir() / 'own_user_agents' / str(yesterday.year) / f'{yesterday.month:02}'
        safe_create_dir(self_generated_ua_file_path)
        self_generated_ua_file = self_generated_ua_file_path / f'{yesterday.isoformat()}.json'
        if self_generated_ua_file.exists():
            return
        entries = self.redis.zrevrange(f'user_agents|{yesterday.isoformat()}', 0, -1)
        if not entries:
            return

        to_store: Dict[str, Any] = {'by_frequency': []}
        uas = Counter([entry.split('|', 1)[1] for entry in entries])
        for ua, _ in uas.most_common():
            parsed_ua = UserAgent(ua)
            if not parsed_ua.platform or not parsed_ua.browser:
                continue
            if parsed_ua.platform not in to_store:
                to_store[parsed_ua.platform] = {}
            if f'{parsed_ua.browser} {parsed_ua.version}' not in to_store[parsed_ua.platform]:
                to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'] = []
            to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'].append(parsed_ua.string)
            to_store['by_frequency'].append({'os': parsed_ua.platform,
                                             'browser': f'{parsed_ua.browser} {parsed_ua.version}',
                                             'useragent': parsed_ua.string})
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2)

        # Remove the UA / IP mapping.
        self.redis.delete(f'user_agents|{yesterday.isoformat()}')

    def _cache_capture(self, capture_uuid: str, /) -> CrawledTree:
        '''Generate the pickle, set the cache, add capture in the indexes'''
        capture_dir = self._get_capture_dir(capture_uuid)
        har_files = sorted(capture_dir.glob('*.har'))
        lock_file = capture_dir / 'lock'
        pickle_file = capture_dir / 'tree.pickle'

        if try_make_file(lock_file):
            # Lock created, we can process
            with lock_file.open('w') as f:
                f.write(datetime.now().isoformat())
        else:
            # The pickle is being created somewhere else, wait until it's done.
            while lock_file.exists():
                time.sleep(5)
            keep_going = 5
            while (ct := load_pickle_tree(capture_dir)) is None:
                keep_going -= 1
                if not keep_going:
                    raise LookylooException(f'Unable to get tree for {capture_uuid}')
                time.sleep(5)
            return ct

        # NOTE: We only index the public captures
        index = True
        try:
            ct = CrawledTree(har_files, capture_uuid)
            self._ensure_meta(capture_dir, ct)
            self._resolve_dns(ct)
            self.context.contextualize_tree(ct)
            # Force update cache of the capture (takes care of the incomplete redirect key)
            self._set_capture_cache(capture_dir, force=True)
            cache = self.capture_cache(capture_uuid)
            if not cache:
                raise LookylooException(f'Broken cache for {capture_dir}')
            if self.is_public_instance:
                if cache.no_index:
                    index = False
            if index:
                self.indexing.index_cookies_capture(ct)
                self.indexing.index_body_hashes_capture(ct)
                self.indexing.index_url_capture(ct)
                categories = list(self.categories_capture(capture_uuid).keys())
                self.indexing.index_categories_capture(capture_uuid, categories)
        except Har2TreeError as e:
            raise NoValidHarFile(e)
        except RecursionError as e:
            raise NoValidHarFile(f'Tree too deep, probably a recursive refresh: {e}.\n Append /export to the URL to get the files.')
        else:
            with pickle_file.open('wb') as _p:
                # Some pickles require a pretty high recursion limit, this kindof fixes it.
                # If the capture is really broken (generally a refresh to self), the capture
                # is discarded in the RecursionError above.
                default_recursion_limit = sys.getrecursionlimit()
                sys.setrecursionlimit(int(default_recursion_limit * 1.1))
                pickle.dump(ct, _p)
                sys.setrecursionlimit(default_recursion_limit)
        finally:
            lock_file.unlink(missing_ok=True)
        return ct

    def _build_cname_chain(self, known_cnames: Dict[str, Optional[str]], hostname) -> List[str]:
        '''Returns a list of CNAMEs starting from one hostname.
        The CNAMEs resolutions are made in `_resolve_dns`. A hostname can have a CNAME entry
        and the CNAME entry can have an other CNAME entry, and so on multiple times.
        This method loops over the hostnames until there are no CNAMES.'''
        cnames: List[str] = []
        to_search = hostname
        while True:
            if known_cnames.get(to_search) is None:
                break
            # At this point, known_cnames[to_search] must exist and be a str
            cnames.append(known_cnames[to_search])  # type: ignore
            to_search = known_cnames[to_search]
        return cnames

    def _resolve_dns(self, ct: CrawledTree):
        '''Resolves all domains of the tree, keeps A (IPv4), AAAA (IPv6), and CNAME entries
        and store them in ips.json and cnames.json, in the capture directory.
        Updates the nodes of the tree accordingly so the information is available.
        '''
        cnames_path = ct.root_hartree.har.path.parent / 'cnames.json'
        ips_path = ct.root_hartree.har.path.parent / 'ips.json'
        host_cnames: Dict[str, Optional[str]] = {}
        if cnames_path.exists():
            with cnames_path.open() as f:
                host_cnames = json.load(f)

        host_ips: Dict[str, List[str]] = {}
        if ips_path.exists():
            with ips_path.open() as f:
                host_ips = json.load(f)

        for node in ct.root_hartree.hostname_tree.traverse():
            if node.name not in host_cnames or node.name not in host_ips:
                # Resolve and cache
                try:
                    response = dns.resolver.resolve(node.name, search=True)
                    for answer in response.response.answer:
                        if answer.rdtype == dns.rdatatype.RdataType.CNAME:
                            host_cnames[str(answer.name).rstrip('.')] = str(answer[0].target).rstrip('.')
                        else:
                            host_cnames[str(answer.name).rstrip('.')] = None

                        if answer.rdtype in [dns.rdatatype.RdataType.A, dns.rdatatype.RdataType.AAAA]:
                            host_ips[str(answer.name).rstrip('.')] = list(set(str(b) for b in answer))
                except Exception:
                    host_cnames[node.name] = None
                    host_ips[node.name] = []
            cnames = self._build_cname_chain(host_cnames, node.name)
            if cnames:
                node.add_feature('cname', cnames)
                if cnames[-1] in host_ips:
                    node.add_feature('resolved_ips', host_ips[cnames[-1]])
            elif node.name in host_ips:
                node.add_feature('resolved_ips', host_ips[node.name])

        with cnames_path.open('w') as f:
            json.dump(host_cnames, f)
        with ips_path.open('w') as f:
            json.dump(host_ips, f)
        return ct

    def get_crawled_tree(self, capture_uuid: str, /) -> CrawledTree:
        '''Get the generated tree in ETE Toolkit format.
        Loads the pickle if it exists, creates it otherwise.'''
        capture_dir = self._get_capture_dir(capture_uuid)
        ct = load_pickle_tree(capture_dir)
        if not ct:
            ct = self._cache_capture(capture_uuid)
        if not ct:
            raise NoValidHarFile(f'Unable to get tree from {capture_dir}')
        return ct

    def add_context(self, capture_uuid: str, /, urlnode_uuid: str, *, ressource_hash: str,
                    legitimate: bool, malicious: bool, details: Dict[str, Dict[str, str]]):
        '''Adds context information to a capture or a URL node'''
        if malicious:
            self.context.add_malicious(ressource_hash, details['malicious'])
        if legitimate:
            self.context.add_legitimate(ressource_hash, details['legitimate'])

    def add_to_legitimate(self, capture_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None):
        '''Mark a full captyre as legitimate.
        Iterates over all the nodes and mark them all as legitimate too.'''
        ct = self.get_crawled_tree(capture_uuid)
        self.context.mark_as_legitimate(ct, hostnode_uuid, urlnode_uuid)

    def remove_pickle(self, capture_uuid: str, /) -> None:
        '''Remove the pickle from a specific capture.'''
        capture_dir = self._get_capture_dir(capture_uuid)
        remove_pickle_tree(capture_dir)

    def rebuild_cache(self) -> None:
        '''Flush and rebuild the redis cache. Doesn't remove the pickles.'''
        self.redis.flushdb()
        self._init_existing_dumps()

    def rebuild_all(self) -> None:
        '''Flush and rebuild the redis cache, and delede all the pickles.'''
        [remove_pickle_tree(capture_dir) for capture_dir in self.capture_dirs]  # type: ignore
        self.rebuild_cache()

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
        ct = self.get_crawled_tree(capture_uuid)
        to_return = {'url': ct.root_url, 'title': ct.root_hartree.har.initial_title,
                     'capture_time': ct.start_time.isoformat(), 'user_agent': ct.user_agent,
                     'referer': ct.referer}
        return to_return

    def get_meta(self, capture_uuid: str, /) -> Dict[str, str]:
        '''Get the meta informations from a capture (mostly, details about the User Agent used.)'''
        capture_dir = self._get_capture_dir(capture_uuid)
        meta = {}
        if (capture_dir / 'meta').exists():
            with open((capture_dir / 'meta'), 'r') as f:
                meta = json.load(f)
        return meta

    def categories_capture(self, capture_uuid: str, /) -> Dict[str, Any]:
        '''Get all the categories related to a capture, in MISP Taxonomies format'''
        capture_dir = self._get_capture_dir(capture_uuid)
        # get existing categories if possible
        if (capture_dir / 'categories').exists():
            with (capture_dir / 'categories').open() as f:
                current_categories = [line.strip() for line in f.readlines()]
            return {e: self.taxonomies.revert_machinetag(e) for e in current_categories}
        return {}

    def categorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Add a category (MISP Taxonomy tag) to a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        # Make sure the category is mappable to a taxonomy.
        self.taxonomies.revert_machinetag(category)

        capture_dir = self._get_capture_dir(capture_uuid)
        # get existing categories if possible
        if (capture_dir / 'categories').exists():
            with (capture_dir / 'categories').open() as f:
                current_categories = set(line.strip() for line in f.readlines())
        else:
            current_categories = set()
        current_categories.add(category)
        with (capture_dir / 'categories').open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

    def uncategorize_capture(self, capture_uuid: str, /, category: str) -> None:
        '''Remove a category (MISP Taxonomy tag) from a capture.'''
        if not get_config('generic', 'enable_categorization'):
            return
        capture_dir = self._get_capture_dir(capture_uuid)
        # get existing categories if possible
        if (capture_dir / 'categories').exists():
            with (capture_dir / 'categories').open() as f:
                current_categories = set(line.strip() for line in f.readlines())
        else:
            current_categories = set()
        current_categories.remove(category)
        with (capture_dir / 'categories').open('w') as f:
            f.writelines(f'{t}\n' for t in current_categories)

    def trigger_modules(self, capture_uuid: str, /, force: bool=False, auto_trigger: bool=False) -> None:
        '''Launch the 3rd party modules on a capture.
        It uses the cached result *if* the module was triggered the same day.
        The `force` flag re-triggers the module regardless of the cache.'''
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_uuid}) is cached.')
            return

        self.pi.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        self.vt.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)
        self.uwhois.capture_default_trigger(ct, force=force, auto_trigger=auto_trigger)

    def get_modules_responses(self, capture_uuid: str, /) -> Optional[Dict[str, Any]]:
        '''Get the responses of the modules from the cached responses on the disk'''
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_uuid}) is cached.')
            return None
        to_return: Dict[str, Any] = {}
        if self.vt.available:
            to_return['vt'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['vt'][redirect] = self.vt.get_url_lookup(redirect)
            else:
                to_return['vt'][ct.root_hartree.har.root_url] = self.vt.get_url_lookup(ct.root_hartree.har.root_url)
        if self.pi.available:
            to_return['pi'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['pi'][redirect] = self.pi.get_url_lookup(redirect)
            else:
                to_return['pi'][ct.root_hartree.har.root_url] = self.pi.get_url_lookup(ct.root_hartree.har.root_url)
        return to_return

    def get_misp_occurrences(self, capture_uuid: str, /) -> Optional[Dict[str, Set[str]]]:
        if not self.misp.available:
            return None
        try:
            ct = self.get_crawled_tree(capture_uuid)
        except LookylooException:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_uuid}) is cached.')
            return None
        nodes_to_lookup = ct.root_hartree.rendered_node.get_ancestors() + [ct.root_hartree.rendered_node]
        to_return: Dict[str, Set[str]] = defaultdict(set)
        for node in nodes_to_lookup:
            hits = self.misp.lookup(node, ct.root_hartree.get_host_node_by_uuid(node.hostnode_uuid))
            for event_id, values in hits.items():
                if not isinstance(values, set):
                    continue
                to_return[event_id].update(values)
        return to_return

    def _set_capture_cache(self, capture_dir: Path, force: bool=False, redis_pipeline: Optional[Redis]=None) -> None:
        '''Populate the redis cache for a capture. Mostly used on the index page.'''
        if force or not self.redis.exists(str(capture_dir)):
            # (re)build cache
            pass
        else:
            return

        with (capture_dir / 'uuid').open() as f:
            uuid = f.read().strip()

        har_files = sorted(capture_dir.glob('*.har'))

        error_cache: Dict[str, str] = {}
        if (capture_dir / 'error.txt').exists():
            # Something went wrong
            with (capture_dir / 'error.txt').open() as _error:
                content = _error.read()
                try:
                    error_to_cache = json.loads(content)
                    if isinstance(error_to_cache, dict) and error_to_cache.get('details'):
                        error_to_cache = error_to_cache.get('details')
                except json.decoder.JSONDecodeError:
                    # old format
                    error_to_cache = content
                error_cache['error'] = f'The capture {capture_dir.name} has an error: {error_to_cache}'

        fatal_error = False
        if har_files:
            try:
                har = HarFile(har_files[0], uuid)
            except Har2TreeError as e:
                error_cache['error'] = str(e)
                fatal_error = True
        else:
            error_cache['error'] = f'No har files in {capture_dir.name}'
            fatal_error = True

        if (capture_dir / 'categories').exists():
            with (capture_dir / 'categories').open() as _categories:
                categories = [c.strip() for c in _categories.readlines()]
        else:
            categories = []

        if not redis_pipeline:
            p = self.redis.pipeline()
        else:
            p = redis_pipeline  # type: ignore
        p.hset('lookup_dirs', uuid, str(capture_dir))
        if error_cache:
            if 'HTTP Error' not in error_cache['error']:
                self.logger.warning(error_cache['error'])
            p.hmset(str(capture_dir), error_cache)  # type: ignore

        if not fatal_error:
            redirects = har.initial_redirects
            incomplete_redirects = False
            if redirects and har.need_tree_redirects:
                # load tree from disk, get redirects
                ct = load_pickle_tree(capture_dir)
                if ct:
                    redirects = ct.redirects
                else:
                    # Pickle not available
                    incomplete_redirects = True

            cache: Dict[str, Union[str, int]] = {'uuid': uuid,
                                                 'title': har.initial_title,
                                                 'timestamp': har.initial_start_time,
                                                 'url': har.root_url,
                                                 'redirects': json.dumps(redirects),
                                                 'categories': json.dumps(categories),
                                                 'capture_dir': str(capture_dir),
                                                 'incomplete_redirects': 1 if incomplete_redirects else 0}
            if (capture_dir / 'no_index').exists():  # If the folders claims anonymity
                cache['no_index'] = 1

            if (capture_dir / 'parent').exists():  # The capture was initiated from an other one
                with (capture_dir / 'parent').open() as f:
                    cache['parent'] = f.read().strip()

            p.hmset(str(capture_dir), cache)  # type: ignore
        if not redis_pipeline:
            p.execute()
        # If the cache is re-created for some reason, pop from the local cache.
        self._captures_index.pop(uuid, None)

    def hide_capture(self, capture_uuid: str, /) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self._get_capture_dir(capture_uuid)
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()
        if capture_uuid in self._captures_index:
            self._captures_index[capture_uuid].no_index = True

    @property
    def capture_uuids(self) -> List[str]:
        '''All the capture UUIDs present in the cache.'''
        return self.redis.hkeys('lookup_dirs')

    def sorted_capture_cache(self, capture_uuids: Optional[Iterable[str]]=None) -> List[CaptureCache]:
        '''Get all the captures in the cache, sorted by timestamp (new -> old).'''
        if capture_uuids is None:
            # Sort all captures
            capture_uuids = self.capture_uuids
        if not capture_uuids:
            # No captures at all on the instance
            return []

        all_cache: List[CaptureCache] = [self._captures_index[uuid] for uuid in capture_uuids if uuid in self._captures_index and not self._captures_index[uuid].incomplete_redirects]

        captures_to_get = set(capture_uuids) - set(self._captures_index.keys())
        if captures_to_get:
            p = self.redis.pipeline()
            for directory in self.redis.hmget('lookup_dirs', *captures_to_get):
                if not directory:
                    continue
                p.hgetall(directory)
            for c in p.execute():
                if not c:
                    continue
                c = CaptureCache(c)
                if c.incomplete_redirects:
                    self._set_capture_cache(c.capture_dir, force=True)
                    c = self.capture_cache(c.uuid)
                if hasattr(c, 'timestamp'):
                    all_cache.append(c)
                    self._captures_index[c.uuid] = c
        all_cache.sort(key=operator.attrgetter('timestamp'), reverse=True)
        return all_cache

    def capture_cache(self, capture_uuid: str, /) -> Optional[CaptureCache]:
        """Get the cache from redis.
        NOTE: Doesn't try to build the pickle"""
        if capture_uuid in self._captures_index:
            return self._captures_index[capture_uuid]
        capture_dir = self._get_capture_dir(capture_uuid)
        cached: Dict[str, Any] = self.redis.hgetall(str(capture_dir))
        if not cached:
            self.logger.warning(f'No cache available for {capture_dir}.')
            return None
        try:
            return CaptureCache(cached)
        except LookylooException as e:
            self.logger.warning(f'Cache ({capture_dir}) is invalid ({e}): {json.dumps(cached, indent=2)}')
            return None

    def _init_existing_dumps(self) -> None:
        '''Initialize the cache for all the captures'''
        p = self.redis.pipeline()
        for capture_dir in self.capture_dirs:
            if capture_dir.exists():
                self._set_capture_cache(capture_dir, redis_pipeline=p)
        p.set('cache_loaded', 1)
        p.execute()

    @property
    def capture_dirs(self) -> List[Path]:
        '''Get all the capture directories, sorder from newest to oldest.'''
        for capture_dir in self.capture_dir.iterdir():
            if capture_dir.is_dir() and not capture_dir.iterdir():
                # Cleanup self.capture_dir of failed runs.
                capture_dir.rmdir()
            if not (capture_dir / 'uuid').exists():
                # Create uuid if missing
                with (capture_dir / 'uuid').open('w') as f:
                    f.write(str(uuid4()))
        return sorted(self.capture_dir.iterdir(), reverse=True)

    def _get_capture_dir(self, capture_uuid: str, /) -> Path:
        '''Use the cache to get a capture directory from a capture UUID'''
        capture_dir: str = self.redis.hget('lookup_dirs', capture_uuid)  # type: ignore
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        to_return = Path(capture_dir)
        if not to_return.exists():
            # The capture was removed, remove the UUID
            self.redis.hdel('lookup_dirs', capture_uuid)
            self.logger.warning(f'UUID ({capture_uuid}) linked to a missing directory ({capture_dir}). Removed now.')
            raise NoValidHarFile(f'UUID ({capture_uuid}) linked to a missing directory ({capture_dir}). Removed now.')
        return to_return

    def get_capture_status(self, capture_uuid: str, /) -> CaptureStatus:
        if self.redis.zrank('to_capture', capture_uuid) is not None:
            return CaptureStatus.QUEUED
        elif self.redis.hexists('lookup_dirs', capture_uuid):
            return CaptureStatus.DONE
        elif self.redis.sismember('ongoing', capture_uuid):
            return CaptureStatus.ONGOING
        return CaptureStatus.UNKNOWN

    def enqueue_capture(self, query: MutableMapping[str, Any], source: str, user: str, authenticated: bool) -> str:
        '''Enqueue a query in the capture queue (used by the UI and the API for asynchronous processing)'''
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        for key, value in query.items():
            if isinstance(value, bool):
                # Yes, empty string because that's False.
                query[key] = 1 if value else ''
            if isinstance(value, list):
                query[key] = json.dumps(value)
        p.hmset(perma_uuid, query)  # type: ignore
        priority = self._get_priority(source, user, authenticated)
        p.zadd('to_capture', {perma_uuid: priority})
        p.zincrby('queues', 1, f'{source}|{authenticated}|{user}')
        p.set(f'{perma_uuid}_mgmt', f'{source}|{authenticated}|{user}')
        p.execute()
        return perma_uuid

    def process_capture_queue(self) -> Union[bool, None]:
        '''Process a query from the capture queue'''
        if not self.redis.exists('to_capture'):
            return None

        status, message = self.splash_status()
        if not status:
            self.logger.critical(f'Splash is not running, unable to process the capture queue: {message}')
            return None

        value = self.redis.zpopmax('to_capture')
        if not value or not value[0]:
            return None
        uuid, score = value[0]
        queue: str = self.redis.get(f'{uuid}_mgmt')  # type: ignore
        self.redis.sadd('ongoing', uuid)

        lazy_cleanup = self.redis.pipeline()
        lazy_cleanup.delete(f'{uuid}_mgmt')
        lazy_cleanup.zincrby('queues', -1, queue)

        to_capture: Dict[str, Union[str, int, float]] = self.redis.hgetall(uuid)
        to_capture['perma_uuid'] = uuid
        if 'cookies' in to_capture:
            to_capture['cookies_pseudofile'] = to_capture.pop('cookies')

        status = self._capture(**to_capture)  # type: ignore
        lazy_cleanup.srem('ongoing', uuid)
        lazy_cleanup.delete(uuid)
        # make sure to expire the key if nothing was process for a while (= queues empty)
        lazy_cleanup.expire('queues', 600)
        lazy_cleanup.execute()
        if status:
            self.logger.info(f'Processed {to_capture["url"]}')
            return True
        self.logger.warning(f'Unable to capture {to_capture["url"]}')
        return False

    def send_mail(self, capture_uuid: str, /, email: str='', comment: str='') -> None:
        '''Send an email notification regarding a specific capture'''
        if not get_config('generic', 'enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        cache = self.capture_cache(capture_uuid)
        if cache:
            initial_url = cache.url
            if cache.redirects:
                redirects = "Redirects:\n"
                redirects += '\n'.join(cache.redirects)
            else:
                redirects = "No redirects."

        email_config = get_config('generic', 'email')
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
            comment=comment,
            sender=msg['From'].addresses[0].display_name,
        )
        msg.set_content(body)
        try:
            s = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
            s.send_message(msg)
            s.quit()
        except Exception as e:
            self.logger.exception(e)
            self.logger.warning(msg.as_string())

    def _ensure_meta(self, capture_dir: Path, tree: CrawledTree) -> None:
        '''Make sure the meta file is present, it contains information about the User Agent used for the capture.'''
        metafile = capture_dir / 'meta'
        if metafile.exists():
            return
        ua = UserAgent(tree.root_hartree.user_agent)
        to_dump = {}
        if ua.platform:
            to_dump['os'] = ua.platform
        if ua.browser:
            if ua.version:
                to_dump['browser'] = f'{ua.browser} {ua.version}'
            else:
                to_dump['browser'] = ua.browser
        if ua.language:
            to_dump['language'] = ua.language

        if not to_dump:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        to_dump['user_agent'] = ua.string
        with metafile.open('w') as f:
            json.dump(to_dump, f)

    def _get_raw(self, capture_uuid: str, /, extension: str='*', all_files: bool=True) -> BytesIO:
        '''Get file(s) from the capture directory'''
        try:
            capture_dir = self._get_capture_dir(capture_uuid)
        except MissingUUID:
            return BytesIO(f'Capture {capture_uuid} not unavailable, try again later.'.encode())
        except NoValidHarFile:
            return BytesIO(f'No capture {capture_uuid} on the system.'.encode())
        all_paths = sorted(list(capture_dir.glob(f'*.{extension}')))
        if not all_files:
            # Only get the first one in the list
            with open(all_paths[0], 'rb') as f:
                return BytesIO(f.read())
        to_return = BytesIO()
        with ZipFile(to_return, 'w') as myzip:
            for path in all_paths:
                if path.name.endswith('pickle'):
                    continue
                myzip.write(path, arcname=f'{capture_dir.name}/{path.name}')
        to_return.seek(0)
        return to_return

    def get_html(self, capture_uuid: str, /, all_html: bool=False) -> BytesIO:
        '''Get rendered HTML'''
        return self._get_raw(capture_uuid, 'html', all_html)

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

    def get_urls_rendered_page(self, capture_uuid: str, /):
        ct = self.get_crawled_tree(capture_uuid)
        return sorted(set(ct.root_hartree.rendered_node.urls_in_rendered_page)
                      - set(ct.root_hartree.all_url_requests.keys()))

    def splash_status(self) -> Tuple[bool, str]:
        try:
            splash_status = requests.get(urljoin(self.splash_url, '_ping'))
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

    def _capture(self, url: str, *, cookies_pseudofile: Optional[Union[BufferedIOBase, str]]=None,
                 depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
                 referer: str='', proxy: str='', perma_uuid: Optional[str]=None, os: Optional[str]=None,
                 browser: Optional[str]=None, parent: Optional[str]=None) -> Union[bool, str]:
        '''Launch a capture'''
        url = url.strip()
        url = refang(url)
        if not url.startswith('http'):
            url = f'http://{url}'
        if self.only_global_lookups:
            splitted_url = urlsplit(url)
            if splitted_url.netloc:
                if splitted_url.hostname:
                    if splitted_url.hostname.split('.')[-1] != 'onion':
                        try:
                            ip = socket.gethostbyname(splitted_url.hostname)
                        except socket.gaierror:
                            self.logger.info('Name or service not known')
                            return False
                        if not ipaddress.ip_address(ip).is_global:
                            return False
            else:
                return False

        cookies = load_cookies(cookies_pseudofile)
        if not user_agent:
            # Catch case where the UA is broken on the UI, and the async submission.
            ua: str = get_config('generic', 'default_user_agent')
        else:
            ua = user_agent

        if int(depth) > int(get_config('generic', 'max_depth')):
            self.logger.warning(f'Not allowed to capture on a depth higher than {get_config("generic", "max_depth")}: {depth}')
            depth = int(get_config('generic', 'max_depth'))
        if not perma_uuid:
            perma_uuid = str(uuid4())
        self.logger.info(f'Capturing {url}')
        try:
            items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                          referer=referer, proxy=proxy, log_enabled=True, log_level=get_config('generic', 'splash_loglevel'))
        except Exception as e:
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            raise e
        if not items:
            # broken
            self.logger.critical(f'Something went terribly wrong when capturing {url}.')
            return False
        width = len(str(len(items)))
        dirpath = self.capture_dir / datetime.now().isoformat()
        safe_create_dir(dirpath)

        if os or browser:
            meta = {}
            if os:
                meta['os'] = os
            if browser:
                meta['browser'] = browser
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(perma_uuid)

        # Write no_index marker (optional)
        if not listing:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if parent:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(parent)

        for i, item in enumerate(items):
            if 'error' in item:
                with (dirpath / 'error.txt').open('w') as _error:
                    json.dump(item['error'], _error)

            # The capture went fine
            harfile = item['har']
            png = base64.b64decode(item['png'])
            html = item['html']
            last_redirect = item['last_redirected_url']

            with (dirpath / '{0:0{width}}.har'.format(i, width=width)).open('w') as _har:
                json.dump(harfile, _har)
            with (dirpath / '{0:0{width}}.png'.format(i, width=width)).open('wb') as _img:
                _img.write(png)
            with (dirpath / '{0:0{width}}.html'.format(i, width=width)).open('w') as _html:
                _html.write(html)
            with (dirpath / '{0:0{width}}.last_redirect.txt'.format(i, width=width)).open('w') as _redir:
                _redir.write(last_redirect)

            if 'childFrames' in item:
                child_frames = item['childFrames']
                with (dirpath / '{0:0{width}}.frames.json'.format(i, width=width)).open('w') as _iframes:
                    json.dump(child_frames, _iframes)

            if 'cookies' in item:
                cookies = item['cookies']
                with (dirpath / '{0:0{width}}.cookies.json'.format(i, width=width)).open('w') as _cookies:
                    json.dump(cookies, _cookies)

        self._set_capture_cache(dirpath)
        return perma_uuid

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
        body_content = BytesIO()
        # get the body from the first entry in the details list
        for _, entries in details.items():
            ct = self.get_crawled_tree(entries[0]['capture'])
            urlnode = ct.root_hartree.get_url_node_by_uuid(entries[0]['urlnode'])
            if urlnode.body_hash == body_hash:
                # the hash we're looking for is the whole file
                body_content = urlnode.body
            else:
                # The hash is an embedded resource
                for _, blobs in urlnode.body_hash.embedded_ressources.items():
                    for h, b in blobs:
                        if h == body_hash:
                            body_content = b
                            break
            break
        return details, body_content

    def get_latest_url_capture(self, url: str, /) -> Optional[CaptureCache]:
        '''Get the most recent capture with this URL'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url))
        if captures:
            return captures[0]
        return None

    def get_url_occurrences(self, url: str, /, limit: int=20) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the URL has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_url(url))

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

    def get_hostname_occurrences(self, hostname: str, /, with_urls_occurrences: bool=False, limit: int=20) -> List[Dict]:
        '''Get the most recent captures and URL nodes where the hostname has been seen.'''
        captures = self.sorted_capture_cache(self.indexing.get_captures_hostname(hostname))

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

    def hash_lookup(self, blob_hash: str, url: str, capture_uuid: str) -> Tuple[int, Dict[str, List[Tuple[str, str, str, str, str]]]]:
        '''Search all the captures a specific hash was seen.
        If a URL is given, it splits the results if the hash is seen on the same URL or an other one.
        Capture UUID avoids duplicates on the same capture'''
        captures_list: Dict[str, List[Tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
        total_captures, details = self.indexing.get_body_hash_captures(blob_hash, url, filter_capture_uuid=capture_uuid)
        for h_capture_uuid, url_uuid, url_hostname, same_url in details:
            cache = self.capture_cache(h_capture_uuid)
            if cache:
                if same_url:
                    captures_list['same_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
                else:
                    captures_list['different_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
        return total_captures, captures_list

    def _normalize_known_content(self, h: str, /, known_content: Dict[str, Any], url: URLNode) -> Tuple[Optional[Union[str, List[Any]]], Optional[Tuple[bool, Any]]]:
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

    def get_ressource(self, tree_uuid: str, /, urlnode_uuid: str, h: Optional[str]) -> Optional[Tuple[str, BytesIO, str]]:
        '''Get a specific resource from a URL node. If a hash s also given, we want an embeded resource'''
        try:
            url = self.get_urlnode_from_tree(tree_uuid, urlnode_uuid)
        except IndexError:
            # unable to find the uuid, the cache is probably in a weird state.
            return None
        if url.empty_response:
            return None
        if not h or h == url.body_hash:
            # we want the body
            return url.filename if url.filename else 'file.bin', url.body, url.mimetype

        # We want an embedded ressource
        if h not in url.resources_hashes:
            return None
        for mimetype, blobs in url.embedded_ressources.items():
            for ressource_h, blob in blobs:
                if ressource_h == h:
                    return 'embedded_ressource.bin', blob, mimetype
        return None

    def __misp_add_ips_to_URLObject(self, obj: URLObject, hostname_tree: HostNode) -> None:
        hosts = obj.get_attributes_by_relation('host')
        if hosts:
            hostnodes = hostname_tree.search_nodes(name=hosts[0].value)
            if hostnodes and hasattr(hostnodes[0], 'resolved_ips'):
                obj.add_attributes('ip', *hostnodes[0].resolved_ips)

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

    def misp_export(self, capture_uuid: str, /, with_parent: bool=False) -> Union[List[MISPEvent], Dict[str, str]]:
        '''Export a capture in MISP format. You can POST the return of this method
        directly to a MISP instance and it will create an event.'''
        cache = self.capture_cache(capture_uuid)
        if not cache:
            return {'error': 'UUID missing in cache, try again later.'}

        if cache.incomplete_redirects:
            self._cache_capture(capture_uuid)
            cache = self.capture_cache(capture_uuid)
            if not cache:
                return {'error': 'UUID missing in cache, try again later.'}

        ct = self.get_crawled_tree(capture_uuid)

        event = MISPEvent()
        event.info = f'Lookyloo Capture ({cache.url})'
        lookyloo_link: MISPAttribute = event.add_attribute('link', f'https://{self.public_domain}/tree/{capture_uuid}')  # type: ignore
        if not self.is_public_instance:
            lookyloo_link.distribution = 0

        initial_url = URLObject(cache.url)
        initial_url.comment = 'Submitted URL'
        self.__misp_add_ips_to_URLObject(initial_url, ct.root_hartree.hostname_tree)

        redirects: List[URLObject] = []
        for nb, url in enumerate(cache.redirects):
            if url == cache.url:
                continue
            obj = URLObject(url)
            obj.comment = f'Redirect {nb}'
            self.__misp_add_ips_to_URLObject(obj, ct.root_hartree.hostname_tree)
            redirects.append(obj)
        if redirects:
            redirects[-1].comment = f'Last redirect ({nb})'

        if redirects:
            prec_object = initial_url
            for u_object in redirects:
                prec_object.add_reference(u_object, 'redirects-to')
                prec_object = u_object

        initial_obj = event.add_object(initial_url)
        initial_obj.add_reference(lookyloo_link, 'captured-by', 'Capture on lookyloo')

        for u_object in redirects:
            event.add_object(u_object)
        final_redirect = event.objects[-1]

        screenshot: MISPAttribute = event.add_attribute('attachment', 'screenshot_landing_page.png', data=self.get_screenshot(capture_uuid), disable_correlation=True)  # type: ignore
        try:
            fo = FileObject(pseudofile=ct.root_hartree.rendered_node.body, filename=ct.root_hartree.rendered_node.filename)
            fo.comment = 'Content received for the final redirect (before rendering)'
            fo.add_reference(final_redirect, 'loaded-by', 'URL loading that content')
            fo.add_reference(screenshot, 'rendered-as', 'Screenshot of the page')
            event.add_object(fo)
        except Har2TreeError:
            pass
        except AttributeError:
            # No `body` in rendered node
            pass

        if self.vt.available:
            for e_obj in event.objects:
                if e_obj.name != 'url':
                    continue
                vt_obj = self.__misp_add_vt_to_URLObject(e_obj)
                if vt_obj:
                    event.add_object(vt_obj)

        if with_parent and cache.parent:
            parent = self.misp_export(cache.parent, with_parent)
            if isinstance(parent, dict):
                # Something bad happened
                return parent

            event.extends_uuid = parent[-1].uuid
            parent.append(event)
            return parent

        return [event]

    def get_hashes(self, tree_uuid: str, /, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> Set[str]:
        """Return hashes of resources.
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

    def get_hostnode_investigator(self, capture_uuid: str, /, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        '''Gather all the informations needed to display the Hostnode investigator popup.'''
        ct = self.get_crawled_tree(capture_uuid)
        hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
        if not hostnode:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {node_uuid}')

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
                        known, legitimate = self._normalize_known_content(h, known_content, url)
                        if known:
                            to_append['embedded_ressources'][h]['known_content'] = known
                        elif legitimate:
                            to_append['embedded_ressources'][h]['legitimacy'] = legitimate

                known, legitimate = self._normalize_known_content(url.body_hash, known_content, url)
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

        for cache in self.sorted_capture_cache():
            date_submission: datetime = cache.timestamp

            if date_submission.year not in stats:
                stats[date_submission.year] = {}
            if date_submission.month not in stats[date_submission.year]:
                stats[date_submission.year][date_submission.month] = defaultdict(dict, **stats_dict)
                stats[date_submission.year][date_submission.month]['uniq_urls'] = set()
            stats[date_submission.year][date_submission.month]['submissions'] += 1
            stats[date_submission.year][date_submission.month]['uniq_urls'].add(cache.url)
            if len(cache.redirects) > 0:
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
                if len(cache.redirects) > 0:
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
