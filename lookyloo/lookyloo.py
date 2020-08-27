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
from typing import Union, Dict, List, Tuple, Optional, Any, MutableMapping, Set, Iterable, Iterator
from urllib.parse import urlsplit
from uuid import uuid4
from zipfile import ZipFile

import publicsuffix2  # type: ignore
from defang import refang  # type: ignore
from har2tree import CrawledTree, Har2TreeError, HarFile, HostNode, URLNode
from redis import Redis
from scrapysplashwrapper import crawl

from werkzeug.useragents import UserAgent

from .exceptions import NoValidHarFile, MissingUUID
from .helpers import get_homedir, get_socket_path, load_cookies, load_configs, safe_create_dir, get_email_template, load_pickle_tree, remove_pickle_tree, load_known_content
from .modules import VirusTotal, SaneJavaScript, PhishingInitiative


def dump_to_json(obj: Union[Set]) -> Union[List]:
    if isinstance(obj, set):
        return list(obj)


class Indexing():

    def __init__(self) -> None:
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    def clear_indexes(self):
        self.redis.flushdb()

    # ###### Cookies ######

    @property
    def cookies_names(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('cookies_names', 0, -1, withscores=True)

    def cookies_names_number_domains(self, cookie_name: str) -> int:
        return self.redis.zcard(f'cn|{cookie_name}')

    def cookies_names_domains_values(self, cookie_name: str, domain: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}|{domain}', 0, -1, withscores=True)

    def get_cookie_domains(self, cookie_name: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}', 0, -1, withscores=True)

    def get_cookies_names_captures(self, cookie_name: str) -> List[Tuple[str, str]]:
        return [uuids.split('|')for uuids in self.redis.smembers(f'cn|{cookie_name}|captures')]

    def index_cookies_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_cookies', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_cookies', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        already_loaded: Set[Tuple[str, str]] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if hasattr(urlnode, 'cookies_received'):
                for domain, cookie, _ in urlnode.cookies_received:
                    name, value = cookie.split('=', 1)
                    if (name, domain) in already_loaded:
                        # Only add cookie name once / capture
                        continue
                    already_loaded.add((name, domain))
                    pipeline.zincrby('cookies_names', 1, name)
                    pipeline.zincrby(f'cn|{name}', 1, domain)
                    pipeline.sadd(f'cn|{name}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
                    pipeline.zincrby(f'cn|{name}|{domain}', 1, value)

                    pipeline.sadd('lookyloo_domains', domain)
                    pipeline.sadd(domain, name)
        pipeline.execute()

    def aggregate_domain_cookies(self):
        psl = publicsuffix2.PublicSuffixList()
        pipeline = self.redis.pipeline()
        for cn, cn_freq in self.cookies_names:
            for domain, d_freq in self.get_cookie_domains(cn):
                tld = psl.get_tld(domain)
                main_domain_part = domain.strip(f'.{tld}').split('.')[-1]
                pipeline.zincrby('aggregate_domains_cn', cn_freq, f'{main_domain_part}|{cn}')
                pipeline.zincrby('aggregate_cn_domains', d_freq, f'{cn}|{main_domain_part}')
        pipeline.execute()
        aggregate_domains_cn = self.redis.zrevrange('aggregate_domains_cn', 0, -1, withscores=True)
        aggregate_cn_domains = self.redis.zrevrange('aggregate_cn_domains', 0, -1, withscores=True)
        self.redis.delete('aggregate_domains_cn')
        self.redis.delete('aggregate_cn_domains')
        return {'domains': aggregate_domains_cn, 'cookies': aggregate_cn_domains}

    # ###### Body hashes ######

    def body_hash_fequency(self, body_hash: str) -> Dict[str, float]:
        return {'hash_freq': self.redis.zscore('body_hashes', body_hash),
                'hash_domains_freq': self.redis.zcard(f'bh|{body_hash}')}

    def index_body_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_body_hashes', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_body_hashes', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if urlnode.empty_response:
                continue
            pipeline.zincrby('body_hashes', 1, urlnode.body_hash)
            pipeline.zincrby(f'bh|{urlnode.body_hash}', 1, urlnode.hostname)
            # set of all captures with this hash
            pipeline.sadd(f'bh|{urlnode.body_hash}|captures', crawled_tree.uuid)
            # ZSet of all urlnode_UUIDs|full_url
            pipeline.zincrby(f'bh|{urlnode.body_hash}|captures|{crawled_tree.uuid}', 1, f'{urlnode.uuid}|{urlnode.hostnode_uuid}|{urlnode.name}')
            if hasattr(urlnode, 'embedded_ressources') and urlnode.embedded_ressources:
                for mimetype, blobs in urlnode.embedded_ressources.items():
                    for h, body in blobs:
                        pipeline.zincrby('body_hashes', 1, h)
                        pipeline.zincrby(f'bh|{h}', 1, urlnode.hostname)
                        pipeline.sadd(f'bh|{h}|captures', crawled_tree.uuid)
                        pipeline.zincrby(f'bh|{h}|captures|{crawled_tree.uuid}', 1,
                                         f'{urlnode.uuid}|{urlnode.hostnode_uuid}|{urlnode.name}')

        pipeline.execute()

    def get_body_hash_captures(self, body_hash: str, filter_url: Optional[str]=None) -> List[Tuple[str, str, str, bool]]:
        to_return: List[Tuple[str, str, str, bool]] = []
        for capture_uuid in self.redis.smembers(f'bh|{body_hash}|captures'):
            for entry in self.redis.zrevrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, -1):
                url_uuid, hostnode_uuid, url = entry.split('|', 2)
                if filter_url:
                    to_return.append((capture_uuid, hostnode_uuid, urlsplit(url).hostname, url == filter_url))
                else:
                    to_return.append((capture_uuid, hostnode_uuid, urlsplit(url).hostname, False))
        return to_return

    def get_body_hash_domains(self, body_hash: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'bh|{body_hash}', 0, -1, withscores=True)


class Context():

    def __init__(self, sanejs: Optional[SaneJavaScript] = None):
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('indexing'), db=1, decode_responses=True)
        self.sanejs = sanejs
        self._cache_known_content()

    def clear_context(self):
        self.redis.flushdb()

    def _get_resources_hashes(self, har2tree_container: Union[CrawledTree, HostNode, URLNode]) -> Set[str]:
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

    def _cache_known_content(self) -> None:
        p = self.redis.pipeline()
        for filename, file_content in load_known_content().items():
            if filename == 'generic':
                for k, type_content in file_content.items():
                    p.hmset('known_content', {h: type_content['description'] for h in type_content['entries']})
            else:
                for mimetype, entry in file_content.items():
                    for h, details in entry.items():
                        p.sadd(f'bh|{h}|legitimate', *details['hostnames'])
        p.execute()

    def find_known_content(self, har2tree_container: Union[CrawledTree, HostNode, URLNode]) -> Dict[str, Union[str, List[str]]]:
        """Return a dictionary of content resources found in the local known_content database, or in SaneJS (if enabled)"""
        all_ressources_hashes = self._get_resources_hashes(har2tree_container)
        # Get from local cache of known content all descriptions related to the ressources.
        if not all_ressources_hashes:
            return {}
        known_content_table = dict(zip(all_ressources_hashes,
                                       self.redis.hmget('known_content', all_ressources_hashes)))

        if self.sanejs and self.sanejs.available:
            # Query sanejs on the remaining ones
            to_lookup = [h for h, description in known_content_table.items() if not description]
            for h, entry in self.sanejs.hashes_lookup(to_lookup).items():
                libname, version, path = entry[0].split("|")
                known_content_table[h] = (libname, version, path, len(entry))
        return {h: details for h, details in known_content_table.items() if details}

    def _filter(self, urlnodes: Union[URLNode, List[URLNode]], known_hashes: Iterable[str]) -> Iterator[Tuple[URLNode, str]]:
        if isinstance(urlnodes, URLNode):
            _urlnodes = [urlnodes]
        else:
            _urlnodes = urlnodes
        for urlnode in _urlnodes:
            for h in urlnode.resources_hashes:
                if h not in known_hashes:
                    yield urlnode, h

    def store_known_legitimate_tree(self, tree: CrawledTree):
        known_content = self.find_known_content(tree)
        urlnodes = tree.root_hartree.url_tree.traverse()
        root_hostname = urlsplit(tree.root_url).hostname
        known_content_file: Path = get_homedir() / 'known_content' / f'{root_hostname}.json'
        if known_content_file.exists():
            with open(known_content_file) as f:
                to_store = json.load(f)
        else:
            to_store = {}
        for urlnode, h in self._filter(urlnodes, known_content):
            if urlnode.mimetype:
                mimetype = urlnode.mimetype.split(';')[0]
            if mimetype not in to_store:
                to_store[mimetype] = {}
            if h not in to_store[mimetype]:
                to_store[mimetype][h] = {'filenames': set(), 'description': '', 'hostnames': set()}
            else:
                to_store[mimetype][h]['filenames'] = set(to_store[mimetype][h]['filenames'])
                to_store[mimetype][h]['hostnames'] = set(to_store[mimetype][h]['hostnames'])

            to_store[mimetype][h]['hostnames'].add(urlnode.hostname)
            if urlnode.url_split.path:
                filename = Path(urlnode.url_split.path).name
                if filename:
                    to_store[mimetype][h]['filenames'].add(filename)

        with open(known_content_file, 'w') as f:
            json.dump(to_store, f, indent=2, default=dump_to_json)

    def mark_as_legitimate(self, tree: CrawledTree, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None) -> None:
        if hostnode_uuid:
            urlnodes = tree.root_hartree.get_host_node_by_uuid(hostnode_uuid).urls
        elif urlnode_uuid:
            urlnodes = [tree.root_hartree.get_url_node_by_uuid(urlnode_uuid)]
        else:
            urlnodes = tree.root_hartree.url_tree.traverse()
            self.store_known_legitimate_tree(tree)
        known_content = self.find_known_content(tree)
        pipeline = self.redis.pipeline()
        for urlnode, h in self._filter(urlnodes, known_content):
            pipeline.sadd(f'bh|{h}|legitimate', urlnode.hostname)
        pipeline.execute()

    def contextualize_tree(self, tree: CrawledTree) -> CrawledTree:
        hostnodes_with_malicious_content = set()
        known_content = self.find_known_content(tree)
        for urlnode in tree.root_hartree.url_tree.traverse():
            malicious = self.is_malicious(urlnode, known_content)
            if malicious is True:
                urlnode.add_feature('malicious', malicious)
                hostnodes_with_malicious_content.add(urlnode.hostnode_uuid)
        for hostnode_with_malicious_content in hostnodes_with_malicious_content:
            hostnode = tree.root_hartree.get_host_node_by_uuid(hostnode_with_malicious_content)
            hostnode.add_feature('malicious', malicious)
        return tree

    def legitimate_body(self, body_hash: str, legitimate_hostname: str) -> None:
        self.redis.sadd(f'bh|{body_hash}|legitimate', legitimate_hostname)

    def malicious_node(self, urlnode: URLNode, known_hashes: Iterable[str]) -> None:
        for _, h in self._filter(urlnode, known_hashes):
            self.redis.sadd('bh|malicious', h)

    # Query DB

    def is_legitimate(self, urlnode: URLNode, known_hashes: Iterable[str]) -> Optional[bool]:
        """3 cases:
            * True if *all* the contents are known legitimate
            * False if *any* content is malicious
            * None in all other cases
        """
        status: List[Optional[bool]] = []
        for urlnode, h in self._filter(urlnode, known_hashes):
            hostnames = self.redis.smembers(f'bh|{h}|legitimate')
            if hostnames:
                if urlnode.hostname in hostnames:
                    status.append(True)  # legitimate
                    continue
                else:
                    return False  # Malicious
            elif self.redis.sismember('bh|malicious', h):
                return False  # Malicious
            else:
                # NOTE: we do not return here, because we want to return False if *any* of the contents is malicious
                status.append(None)  # Unknown
        if status and all(status):
            return True  # All the contents are known legitimate
        return None

    def is_malicious(self, urlnode: URLNode, known_hashes: Iterable[str]) -> Optional[bool]:
        """3 cases:
            * True if *any* content is malicious
            * False if *all* the contents are known legitimate
            * None in all other cases
        """
        legitimate = self.is_legitimate(urlnode, known_hashes)
        if legitimate:
            return False
        elif legitimate is False:
            return True
        return None

    def legitimacy_details(self, urlnode: URLNode, known_hashes: Iterable[str]) -> Dict[str, Tuple[bool, Optional[List[str]]]]:
        to_return = {}
        for urlnode, h in self._filter(urlnode, known_hashes):
            hostnames = self.redis.smembers(f'bh|{h}|legitimate')
            if hostnames:
                if urlnode.hostname in hostnames:
                    to_return[h] = (True, hostnames)
                else:
                    to_return[h] = (False, hostnames)
            elif self.redis.sismember('bh|malicious', urlnode.body_hash):
                to_return[h] = (False, None)
        return to_return


class Lookyloo():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.configs: Dict[str, Dict[str, Any]] = load_configs()
        self.logger.setLevel(self.get_config('loglevel'))
        self.indexing = Indexing()
        self.is_public_instance = self.get_config('public_instance')

        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.scrape_dir: Path = get_homedir() / 'scraped'
        if os.environ.get('SPLASH_URL_DOCKER'):
            # In order to have a working default for the docker image, it is easier to use an environment variable
            self.splash_url: str = os.environ['SPLASH_URL_DOCKER']
        else:
            self.splash_url = self.get_config('splash_url')
        self.only_global_lookups: bool = self.get_config('only_global_lookups')

        safe_create_dir(self.scrape_dir)

        # Initialize 3rd party components
        if 'modules' not in self.configs:
            self.logger.info('No third party components available in the config directory')
        else:
            if 'PhishingInitiative' in self.configs['modules']:
                self.pi = PhishingInitiative(self.configs['modules']['PhishingInitiative'])
                if not self.pi.available:
                    self.logger.warning('Unable to setup the PhishingInitiative module')
            if 'VirusTotal' in self.configs['modules']:
                self.vt = VirusTotal(self.configs['modules']['VirusTotal'])
                if not self.vt.available:
                    self.logger.warning('Unable to setup the VirusTotal module')
            if 'SaneJS' in self.configs['modules']:
                self.sanejs = SaneJavaScript(self.configs['modules']['SaneJS'])
                if not self.sanejs.available:
                    self.logger.warning('Unable to setup the SaneJS module')

        if hasattr(self, 'sanejs') and self.sanejs.available:
            self.context = Context(self.sanejs)
        else:
            self.context = Context()

        if not self.redis.exists('cache_loaded'):
            self._init_existing_dumps()

    def cache_user_agents(self, user_agent: str, remote_ip: str) -> None:
        today = date.today().isoformat()
        self.redis.zincrby(f'user_agents|{today}', 1, f'{remote_ip}|{user_agent}')

    def build_ua_file(self) -> None:
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
        for ua, count in uas.most_common():
            parsed_ua = UserAgent(ua)
            if not parsed_ua.platform or not parsed_ua.browser:  # type: ignore
                continue
            if parsed_ua.platform not in to_store:  # type: ignore
                to_store[parsed_ua.platform] = {}  # type: ignore
            if f'{parsed_ua.browser} {parsed_ua.version}' not in to_store[parsed_ua.platform]:  # type: ignore
                to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'] = []  # type: ignore
            to_store[parsed_ua.platform][f'{parsed_ua.browser} {parsed_ua.version}'].append(parsed_ua.string)  # type: ignore
            to_store['by_frequency'].append({'os': parsed_ua.platform,  # type: ignore
                                             'browser': f'{parsed_ua.browser} {parsed_ua.version}',  # type: ignore
                                             'useragent': parsed_ua.string})  # type: ignore
        with self_generated_ua_file.open('w') as f:
            json.dump(to_store, f, indent=2)

    def cache_tree(self, capture_uuid: str) -> None:
        '''Generate the pickle, add capture in the indexes'''
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')

        with open((capture_dir / 'uuid'), 'r') as f:
            uuid = f.read()
        har_files = sorted(capture_dir.glob('*.har'))
        # NOTE: We only index the public captures
        index = True
        try:
            ct = CrawledTree(har_files, uuid)
            if self.is_public_instance:
                cache = self.capture_cache(capture_uuid)
                if cache.get('no_index') is not None:
                    index = False
            if index:
                self.indexing.index_cookies_capture(ct)
                self.indexing.index_body_hashes_capture(ct)
        except Har2TreeError as e:
            raise NoValidHarFile(e.message)

        with (capture_dir / 'tree.pickle').open('wb') as _p:
            pickle.dump(ct, _p)

    def get_crawled_tree(self, capture_uuid: str) -> CrawledTree:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.cache_tree(capture_uuid)
            ct = load_pickle_tree(capture_dir)

        if not ct:
            raise NoValidHarFile(f'Unable to get tree from {capture_dir}')

        return ct

    def add_to_legitimate(self, capture_uuid: str, hostnode_uuid: Optional[str]=None, urlnode_uuid: Optional[str]=None):
        ct = self.get_crawled_tree(capture_uuid)
        self.context.mark_as_legitimate(ct, hostnode_uuid, urlnode_uuid)

    def load_tree(self, capture_uuid: str) -> Tuple[str, str, str, str, Dict[str, str]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        meta = {}
        if (capture_dir / 'meta').exists():
            with open((capture_dir / 'meta'), 'r') as f:
                meta = json.load(f)
        ct = self.get_crawled_tree(capture_uuid)
        ct = self.context.contextualize_tree(ct)
        return ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url, meta

    def remove_pickle(self, capture_uuid: str) -> None:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        remove_pickle_tree(capture_dir)

    def rebuild_cache(self) -> None:
        self.redis.flushdb()
        self._init_existing_dumps()

    def rebuild_all(self) -> None:
        for capture_dir in self.capture_dirs:
            remove_pickle_tree(capture_dir)
        self.rebuild_cache()

    def get_config(self, entry: str) -> Any:
        """Get an entry from the generic config file. Automatic fallback to the sample file"""
        if 'generic' in self.configs:
            if entry in self.configs['generic']:
                return self.configs['generic'][entry]
            else:
                self.logger.warning(f'Unable to find {entry} in config file.')
        else:
            self.logger.warning('No generic config file available.')
        self.logger.warning('Falling back on sample config, please initialize the generic config file.')
        with (get_homedir() / 'config' / 'generic.json.sample').open() as _c:
            sample_config = json.load(_c)
        return sample_config[entry]

    def get_urlnode_from_tree(self, capture_uuid: str, node_uuid: str) -> URLNode:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_url_node_by_uuid(node_uuid)

    def get_hostnode_from_tree(self, capture_uuid: str, node_uuid: str) -> HostNode:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')
        return ct.root_hartree.get_host_node_by_uuid(node_uuid)

    def get_statistics(self, capture_uuid: str) -> Dict[str, Any]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return {}
        return ct.root_hartree.stats

    def trigger_modules(self, capture_uuid: str, force: bool=False) -> None:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.logger.warning(f'Unable to trigger the modules unless the tree ({capture_dir}) is cached.')
            return

        if hasattr(self, 'pi') and self.pi.available:
            if ct.redirects:
                for redirect in ct.redirects:
                    self.pi.url_lookup(redirect, force)
            else:
                self.pi.url_lookup(ct.root_hartree.har.root_url, force)

        if hasattr(self, 'vt') and self.vt.available:
            if ct.redirects:
                for redirect in ct.redirects:
                    self.vt.url_lookup(redirect, force)
            else:
                self.vt.url_lookup(ct.root_hartree.har.root_url, force)

    def get_modules_responses(self, capture_uuid: str) -> Optional[Dict[str, Any]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        ct = load_pickle_tree(capture_dir)
        if not ct:
            self.logger.warning(f'Unable to get the modules responses unless the tree ({capture_dir}) is cached.')
            return None
        to_return: Dict[str, Any] = {}
        if hasattr(self, 'vt') and self.vt.available:
            to_return['vt'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['vt'][redirect] = self.vt.get_url_lookup(redirect)
            else:
                to_return['vt'][ct.root_hartree.har.root_url] = self.vt.get_url_lookup(ct.root_hartree.har.root_url)
        if hasattr(self, 'pi') and self.pi.available:
            to_return['pi'] = {}
            if ct.redirects:
                for redirect in ct.redirects:
                    to_return['pi'][redirect] = self.pi.get_url_lookup(redirect)
            else:
                to_return['pi'][ct.root_hartree.har.root_url] = self.pi.get_url_lookup(ct.root_hartree.har.root_url)
        return to_return

    def _set_capture_cache(self, capture_dir: Path, force: bool=False) -> None:
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
            with (Path(capture_dir) / 'error.txt').open() as _error:
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
                error_cache['error'] = e.message
                fatal_error = True
        else:
            error_cache['error'] = f'No har files in {capture_dir.name}'
            fatal_error = True

        if error_cache:
            self.logger.warning(error_cache['error'])
            self.redis.hmset(str(capture_dir), error_cache)
            self.redis.hset('lookup_dirs', uuid, str(capture_dir))

        if fatal_error:
            return

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
                                             'capture_dir': str(capture_dir),
                                             'incomplete_redirects': 1 if incomplete_redirects else 0}
        if (capture_dir / 'no_index').exists():  # If the folders claims anonymity
            cache['no_index'] = 1

        self.redis.hmset(str(capture_dir), cache)
        self.redis.hset('lookup_dirs', uuid, str(capture_dir))

    def hide_capture(self, capture_uuid: str) -> None:
        """Add the capture in the hidden pool (not shown on the front page)
        NOTE: it won't remove the correlations until they are rebuilt.
        """
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        self.redis.hset(str(capture_dir), 'no_index', 1)
        (capture_dir / 'no_index').touch()

    @property
    def capture_uuids(self):
        return self.redis.hkeys('lookup_dirs')

    def capture_cache(self, capture_uuid: str) -> Dict[str, Any]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
        if self.redis.hget(str(capture_dir), 'incomplete_redirects') == '1':
            # try to rebuild the cache
            self._set_capture_cache(capture_dir, force=True)
        cached = self.redis.hgetall(str(capture_dir))
        if all(key in cached.keys() for key in ['uuid', 'title', 'timestamp', 'url', 'redirects', 'capture_dir']):
            cached['redirects'] = json.loads(cached['redirects'])
            cached['capture_dir'] = Path(cached['capture_dir'])
            return cached
        elif 'error' in cached:
            return cached
        else:
            self.logger.warning(f'Cache ({capture_dir}) is invalid: {json.dumps(cached, indent=2)}')
            return {}

    def _init_existing_dumps(self) -> None:
        for capture_dir in self.capture_dirs:
            if capture_dir.exists():
                self._set_capture_cache(capture_dir)
        self.redis.set('cache_loaded', 1)

    @property
    def capture_dirs(self) -> List[Path]:
        for capture_dir in self.scrape_dir.iterdir():
            if capture_dir.is_dir() and not capture_dir.iterdir():
                # Cleanup self.scrape_dir of failed runs.
                capture_dir.rmdir()
            if not (capture_dir / 'uuid').exists():
                # Create uuid if missing
                with (capture_dir / 'uuid').open('w') as f:
                    f.write(str(uuid4()))
        return sorted(self.scrape_dir.iterdir(), reverse=True)

    def lookup_capture_dir(self, capture_uuid: str) -> Union[Path, None]:
        capture_dir = self.redis.hget('lookup_dirs', capture_uuid)
        if capture_dir:
            return Path(capture_dir)
        return None

    def enqueue_scrape(self, query: MutableMapping[str, Any]) -> str:
        perma_uuid = str(uuid4())
        p = self.redis.pipeline()
        for key, value in query.items():
            if isinstance(value, bool):
                # Yes, empty string because that's False.
                query[key] = 1 if value else ''
        p.hmset(perma_uuid, query)
        p.sadd('to_scrape', perma_uuid)
        p.execute()
        return perma_uuid

    def process_scrape_queue(self) -> Union[bool, None]:
        uuid = self.redis.spop('to_scrape')
        if not uuid:
            return None
        to_scrape = self.redis.hgetall(uuid)
        self.redis.delete(uuid)
        to_scrape['perma_uuid'] = uuid
        if self.scrape(**to_scrape):
            self.logger.info(f'Processed {to_scrape["url"]}')
            return True
        return False

    def send_mail(self, capture_uuid: str, email: str='', comment: str='') -> None:
        if not self.get_config('enable_mail_notification'):
            return

        redirects = ''
        initial_url = ''
        cache = self.capture_cache(capture_uuid)
        if cache:
            initial_url = cache['url']
            if 'redirects' in cache and cache['redirects']:
                redirects = "Redirects:\n"
                redirects += '\n'.join(cache['redirects'])
            else:
                redirects = "No redirects."

        email_config = self.get_config('email')
        msg = EmailMessage()
        msg['From'] = email_config['from']
        if email:
            msg['Reply-To'] = email
        msg['To'] = email_config['to']
        msg['Subject'] = email_config['subject']
        body = get_email_template()
        body = body.format(
            recipient=msg['To'].addresses[0].display_name,
            domain=email_config['domain'],
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
        metafile = capture_dir / 'meta'
        if metafile.exists():
            return
        ua = UserAgent(tree.root_hartree.user_agent)
        to_dump = {}
        if ua.platform:  # type: ignore
            to_dump['os'] = ua.platform  # type: ignore
        if ua.browser:  # type: ignore
            if ua.version:  # type: ignore
                to_dump['browser'] = f'{ua.browser} {ua.version}'  # type: ignore
            else:
                to_dump['browser'] = ua.browser  # type: ignore
        if ua.language:  # type: ignore
            to_dump['language'] = ua.language  # type: ignore

        if not to_dump:
            # UA not recognized
            self.logger.info(f'Unable to recognize the User agent: {ua}')
        to_dump['user_agent'] = ua.string  # type: ignore
        with metafile.open('w') as f:
            json.dump(to_dump, f)

    def _get_raw(self, capture_uuid: str, extension: str='*', all_files: bool=True) -> BytesIO:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find UUID {capture_uuid} in the cache')
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

    def get_html(self, capture_uuid: str, all_html: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'html', all_html)

    def get_cookies(self, capture_uuid: str, all_cookies: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'cookies.json', all_cookies)

    def get_screenshot(self, capture_uuid: str, all_images: bool=False) -> BytesIO:
        return self._get_raw(capture_uuid, 'png', all_images)

    def get_capture(self, capture_uuid: str) -> BytesIO:
        return self._get_raw(capture_uuid)

    def scrape(self, url: str, cookies_pseudofile: Optional[BufferedIOBase]=None,
               depth: int=1, listing: bool=True, user_agent: Optional[str]=None,
               referer: str='', perma_uuid: str=None, os: str=None,
               browser: str=None) -> Union[bool, str]:
        url = url.strip()
        url = refang(url)
        if not url.startswith('http'):
            url = f'http://{url}'
        if self.only_global_lookups:
            splitted_url = urlsplit(url)
            if splitted_url.netloc:
                if splitted_url.hostname:
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
            ua: str = self.get_config('default_user_agent')  # type: ignore
        else:
            ua = user_agent

        if int(depth) > int(self.get_config('max_depth')):  # type: ignore
            self.logger.warning(f'Not allowed to scrape on a depth higher than {self.get_config("max_depth")}: {depth}')
            depth = int(self.get_config('max_depth'))  # type: ignore
        items = crawl(self.splash_url, url, cookies=cookies, depth=depth, user_agent=ua,
                      referer=referer, log_enabled=True, log_level=self.get_config('splash_loglevel'))
        if not items:
            # broken
            return False
        if not perma_uuid:
            perma_uuid = str(uuid4())
        width = len(str(len(items)))
        dirpath = self.scrape_dir / datetime.now().isoformat()
        safe_create_dir(dirpath)
        for i, item in enumerate(items):
            if not listing:  # Write no_index marker
                (dirpath / 'no_index').touch()
            with (dirpath / 'uuid').open('w') as _uuid:
                _uuid.write(perma_uuid)
            if os or browser:
                meta = {}
                if os:
                    meta['os'] = os
                if browser:
                    meta['browser'] = browser
                with (dirpath / 'meta').open('w') as _meta:
                    json.dump(meta, _meta)

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

    def get_body_hash_investigator(self, body_hash: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, float]]]:
        captures = []
        for capture_uuid, url_uuid, url_hostname, _ in self.indexing.get_body_hash_captures(body_hash):
            cache = self.capture_cache(capture_uuid)
            if cache:
                captures.append((capture_uuid, cache['title']))
        domains = self.indexing.get_body_hash_domains(body_hash)
        return captures, domains

    def get_cookie_name_investigator(self, cookie_name: str):
        captures = []
        for capture_uuid, url_uuid in self.indexing.get_cookies_names_captures(cookie_name):
            cache = self.capture_cache(capture_uuid)
            if cache:
                captures.append((capture_uuid, cache['title']))
        domains = [(domain, freq, self.indexing.cookies_names_domains_values(cookie_name, domain))
                   for domain, freq in self.indexing.get_cookie_domains(cookie_name)]
        return captures, domains

    def hash_lookup(self, blob_hash: str, url: str, capture_uuid: str) -> Dict[str, List[Tuple[str, str, str, str, str]]]:
        captures_list: Dict[str, List[Tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
        for h_capture_uuid, url_uuid, url_hostname, same_url in self.indexing.get_body_hash_captures(blob_hash, url):
            if h_capture_uuid == capture_uuid:
                # Skip self.
                continue
            cache = self.capture_cache(h_capture_uuid)
            if cache:
                if same_url:
                    captures_list['same_url'].append((h_capture_uuid, url_uuid, cache['title'], cache['timestamp'], url_hostname))
                else:
                    captures_list['different_url'].append((h_capture_uuid, url_uuid, cache['title'], cache['timestamp'], url_hostname))
        return captures_list

    def get_hostnode_investigator(self, capture_uuid: str, node_uuid: str) -> Tuple[HostNode, List[Dict[str, Any]]]:
        capture_dir = self.lookup_capture_dir(capture_uuid)
        if not capture_dir:
            raise MissingUUID(f'Unable to find {capture_uuid}')

        ct = load_pickle_tree(capture_dir)
        if not ct:
            raise MissingUUID(f'Unable to find {capture_dir}')
        hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
        if not hostnode:
            raise MissingUUID(f'Unable to find UUID {node_uuid} in {capture_dir}')

        known_content = self.context.find_known_content(hostnode)

        urls: List[Dict[str, Any]] = []
        for url in hostnode.urls:
            # For the popup, we need:
            # * https vs http
            # * everything after the domain
            # * the full URL
            legit_details = self.context.legitimacy_details(url, known_content)
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
                        to_append['embedded_ressources'][h]['known_content'] = known_content.get(h)
                        to_append['embedded_ressources'][h]['legitimacy'] = legit_details.get(h)

                to_append['known_content'] = known_content.get(url.body_hash)
                to_append['legitimacy'] = legit_details.get(url.body_hash)

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
