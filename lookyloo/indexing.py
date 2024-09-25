#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import logging

from io import BytesIO
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from zipfile import ZipFile

import mmh3

from bs4 import BeautifulSoup
from hashlib import sha256
from pathlib import Path

from har2tree import CrawledTree
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .exceptions import NoValidHarFile, TreeNeedsRebuild
from .helpers import load_pickle_tree
from .default import get_socket_path, get_config


class Indexing():

    def __init__(self, full_index: bool=False) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.__redis_pool_bytes: ConnectionPool
        self.__redis_pool: ConnectionPool
        if full_index:
            self.__redis_pool_bytes = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                     path=get_socket_path('full_index'))
            self.__redis_pool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                               path=get_socket_path('full_index'), decode_responses=True)
        else:
            self.__redis_pool_bytes = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                     path=get_socket_path('indexing'))
            self.__redis_pool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                               path=get_socket_path('indexing'), decode_responses=True)

    def clear_indexes(self) -> None:
        self.redis.flushdb()

    @property
    def redis_bytes(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.__redis_pool_bytes)

    @property
    def redis(self) -> Redis:  # type: ignore[type-arg]
        return Redis(connection_pool=self.__redis_pool)

    def can_index(self, capture_uuid: str | None=None) -> bool:
        if capture_uuid:
            return bool(self.redis.set(f'ongoing_indexing|{capture_uuid}', 1, ex=360, nx=True))

        return bool(self.redis.set('ongoing_indexing', 1, ex=3600, nx=True))

    def indexing_done(self, capture_uuid: str | None=None) -> None:
        if capture_uuid:
            self.redis.delete(f'ongoing_indexing|{capture_uuid}')
        else:
            self.redis.delete('ongoing_indexing')

    def force_reindex(self, capture_uuid: str) -> None:
        p = self.redis.pipeline()
        p.srem('indexed_urls', capture_uuid)
        p.srem('indexed_body_hashes', capture_uuid)
        p.srem('indexed_cookies', capture_uuid)
        p.srem('indexed_hhhashes', capture_uuid)
        p.srem('indexed_favicons', capture_uuid)
        p.srem('indexed_identifiers', capture_uuid)
        p.srem('indexed_categories', capture_uuid)
        p.srem('indexed_tlds', capture_uuid)
        for identifier_type in self.identifiers_types():
            p.srem(f'indexed_identifiers|{identifier_type}|captures', capture_uuid)
        for hash_type in self.captures_hashes_types():
            p.srem(f'indexed_hash_type|{hash_type}', capture_uuid)
        for internal_index in self.redis.smembers(f'capture_indexes|{capture_uuid}'):
            # internal_index can be "tlds"
            for entry in self.redis.smembers(f'capture_indexes|{capture_uuid}|{internal_index}'):
                # entry can be a "com", we delete a set of UUIDs, remove from the captures set
                p.delete(f'capture_indexes|{capture_uuid}|{internal_index}|{entry}')
                p.zrem(f'{internal_index}|{entry}|captures', capture_uuid)
            p.delete(f'capture_indexes|{capture_uuid}|{internal_index}')
        p.delete(f'capture_indexes|{capture_uuid}')
        p.execute()

    def capture_indexed(self, capture_uuid: str) -> tuple[bool, bool, bool, bool, bool, bool, bool, bool, bool]:
        p = self.redis.pipeline()
        p.sismember('indexed_urls', capture_uuid)
        p.sismember('indexed_body_hashes', capture_uuid)
        p.sismember('indexed_cookies', capture_uuid)
        p.sismember('indexed_hhhashes', capture_uuid)
        p.sismember('indexed_favicons', capture_uuid)
        p.sismember('indexed_identifiers', capture_uuid)
        p.sismember('indexed_categories', capture_uuid)
        p.sismember('indexed_tlds', capture_uuid)
        # We also need to check if the hash_type are all indexed for this capture
        hash_types_indexed = all(self.redis.sismember(f'indexed_hash_type|{hash_type}', capture_uuid) for hash_type in self.captures_hashes_types())
        to_return: list[bool] = p.execute()
        to_return.append(hash_types_indexed)
        # This call for sure returns a tuple of 8 booleans
        return tuple(to_return)  # type: ignore[return-value]

    def index_capture(self, uuid_to_index: str, directory: Path) -> None:
        if self.redis.sismember('nothing_to_index', uuid_to_index):
            # No HAR file in the capture, break immediately.
            return
        if not self.can_index(uuid_to_index):
            self.logger.info(f'Indexing on {uuid_to_index} ongoing, skipping. ')
            return

        try:
            indexed = self.capture_indexed(uuid_to_index)
            if all(indexed):
                return

            if not list(directory.rglob('*.har.gz')) and not list(directory.rglob('*.har')):
                self.logger.debug(f'No harfile in {uuid_to_index} - {directory}, nothing to index. ')
                self.redis.sadd('nothing_to_index', uuid_to_index)
                return

            if not any((directory / pickle_name).exists()
                       for pickle_name in ['tree.pickle.gz', 'tree.pickle']):
                self.logger.warning(f'No pickle for {uuid_to_index} - {directory}, skipping. ')
                return

            # do the indexing
            ct = load_pickle_tree(directory, directory.stat().st_mtime, self.logger)
            if not indexed[0]:
                self.logger.info(f'Indexing urls for {uuid_to_index}')
                self.index_url_capture(ct)
            if not indexed[1]:
                self.logger.info(f'Indexing resources for {uuid_to_index}')
                self.index_body_hashes_capture(ct)
            if not indexed[2]:
                self.logger.info(f'Indexing cookies for {uuid_to_index}')
                self.index_cookies_capture(ct)
            if not indexed[3]:
                self.logger.info(f'Indexing HH Hashes for {uuid_to_index}')
                self.index_http_headers_hashes_capture(ct)
            if not indexed[4]:
                self.logger.info(f'Indexing favicons for {uuid_to_index}')
                self.index_favicons_capture(uuid_to_index, directory)
            if not indexed[5]:
                self.logger.info(f'Indexing identifiers for {uuid_to_index}')
                self.index_identifiers_capture(ct)
            if not indexed[6]:
                self.logger.info(f'Indexing categories for {uuid_to_index}')
                self.index_categories_capture(uuid_to_index, directory)
            if not indexed[7]:
                self.logger.info(f'Indexing TLDs for {uuid_to_index}')
                self.index_tld_capture(ct)
            if not indexed[8]:
                self.logger.info(f'Indexing hash types for {uuid_to_index}')
                self.index_capture_hashes_types(ct)

        except (TreeNeedsRebuild, NoValidHarFile) as e:
            self.logger.warning(f'Error loading the pickle for {uuid_to_index}: {e}')
        except Exception as e:
            self.logger.warning(f'Error during indexing for {uuid_to_index}: {e}')
        finally:
            self.indexing_done(uuid_to_index)

    # ###### Cookies ######

    @property
    def cookies_names(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('cookies_names', 0, -1, withscores=True)

    def cookies_names_number_domains(self, cookie_name: str) -> int:
        return self.redis.zcard(f'cn|{cookie_name}')

    def cookies_names_domains_values(self, cookie_name: str, domain: str) -> list[tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}|{domain}', 0, -1, withscores=True)

    def get_cookie_domains(self, cookie_name: str) -> list[tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}', 0, -1, withscores=True)

    def get_cookies_names_captures(self, cookie_name: str) -> list[tuple[str, str]]:
        return [uuids.split('|') for uuids in self.redis.smembers(f'cn|{cookie_name}|captures')]

    def index_cookies_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_cookies', crawled_tree.uuid):
            # Do not reindex
            return
        self.logger.debug(f'Indexing cookies for {crawled_tree.uuid} ... ')
        self.redis.sadd('indexed_cookies', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        already_loaded: set[tuple[str, str]] = set()
        # used if we need to reindex a capture
        already_cleaned_up: set[str] = set()
        is_reindex = False
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if 'cookies_received' not in urlnode.features:
                continue
            for domain, cookie, _ in urlnode.cookies_received:
                name, value = cookie.split('=', 1)
                if (name, domain) in already_loaded:
                    # Only add cookie name once / capture
                    continue
                already_loaded.add((name, domain))
                if name not in already_cleaned_up:
                    # We only run this srem once per name for a capture,
                    # before adding it for the first time
                    to_remove = [key for key in self.redis.sscan_iter(f'cn|{name}|captures', f'{crawled_tree.uuid}|*')]
                    if to_remove:
                        pipeline.srem(f'cn|{name}|captures', *to_remove)
                        is_reindex = True
                        self.logger.debug(f'reindexing cookies for {crawled_tree.uuid} ... ')
                    already_cleaned_up.add(name)
                pipeline.sadd(f'cn|{name}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
                if not is_reindex:
                    pipeline.zincrby('cookies_names', 1, name)
                    pipeline.zincrby(f'cn|{name}', 1, domain)
                    pipeline.zincrby(f'cn|{name}|{domain}', 1, value)
                    pipeline.sadd(domain, name)
        pipeline.execute()
        self.logger.debug(f'done with cookies for {crawled_tree.uuid}.')

    # ###### Body hashes ######

    @property
    def ressources(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('body_hashes', 0, 200, withscores=True)

    def ressources_number_domains(self, h: str) -> int:
        return self.redis.zcard(f'bh|{h}')

    def body_hash_fequency(self, body_hash: str) -> dict[str, int]:
        pipeline = self.redis.pipeline()
        pipeline.zscore('body_hashes', body_hash)
        pipeline.zcard(f'bh|{body_hash}')
        hash_freq, hash_domains_freq = pipeline.execute()
        to_return = {'hash_freq': 0, 'hash_domains_freq': 0}
        if hash_freq:
            to_return['hash_freq'] = int(hash_freq)
        if hash_domains_freq:
            to_return['hash_domains_freq'] = int(hash_domains_freq)
        return to_return

    def index_body_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_body_hashes', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_body_hashes', crawled_tree.uuid)
        self.logger.debug(f'Indexing body hashes for {crawled_tree.uuid} ... ')

        cleaned_up_hashes: set[str] = set()
        pipeline = self.redis.pipeline()
        is_reindex = False
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            for h in urlnode.resources_hashes:
                if h not in cleaned_up_hashes:
                    # Delete the hash for that capture the first time we see it.
                    if self.redis.exists(f'bh|{h}|captures|{crawled_tree.uuid}'):
                        pipeline.delete(f'bh|{h}|captures|{crawled_tree.uuid}')
                        cleaned_up_hashes.add(h)
                        is_reindex = True
                        self.logger.debug(f'reindexing body hashes for {crawled_tree.uuid} ... ')
                # ZSet of all urlnode_UUIDs|full_url
                pipeline.zincrby(f'bh|{h}|captures|{crawled_tree.uuid}', 1,
                                 f'{urlnode.uuid}|{urlnode.hostnode_uuid}|{urlnode.name}')
                if not is_reindex:
                    pipeline.zincrby('body_hashes', 1, h)
                    pipeline.zincrby(f'bh|{h}', 1, urlnode.hostname)
                    # set of all captures with this hash
                    pipeline.sadd(f'bh|{h}|captures', crawled_tree.uuid)
        pipeline.execute()
        self.logger.debug(f'done with body hashes for {crawled_tree.uuid}.')

    def get_hash_uuids(self, body_hash: str) -> tuple[str, str, str]:
        """Use that to get a reference allowing to fetch a resource from one of the capture."""
        capture_uuid = str(self.redis.srandmember(f'bh|{body_hash}|captures'))
        entry = self.redis.zrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, 1)[0]
        urlnode_uuid, hostnode_uuid, url = entry.split('|', 2)
        return capture_uuid, urlnode_uuid, hostnode_uuid

    def get_body_hash_captures(self, body_hash: str, filter_url: str | None=None,
                               filter_capture_uuid: str | None=None,
                               limit: int=20,
                               prefered_uuids: set[str]=set()) -> tuple[int, list[tuple[str, str, str, bool, str]]]:
        '''Get the captures matching the hash.

        :param filter_url: URL of the hash we're searching for
        :param filter_capture_uuid: UUID of the capture the hash was found in
        :param limit: Max matching captures to return, -1 means unlimited.
        :param prefered_uuids: UUID cached right now, so we don't rebuild trees.
        '''
        to_return: list[tuple[str, str, str, bool, str]] = []
        len_captures = self.redis.scard(f'bh|{body_hash}|captures')
        unlimited = False
        if limit == -1:
            unlimited = True
        for capture_uuid in self.redis.sscan_iter(f'bh|{body_hash}|captures'):
            if capture_uuid == filter_capture_uuid:
                # Used to skip hits in current capture
                len_captures -= 1
                continue
            if prefered_uuids and capture_uuid not in prefered_uuids:
                continue
            if not unlimited:
                limit -= 1
            for entry in self.redis.zrevrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, -1):
                url_uuid, hostnode_uuid, url = entry.split('|', 2)
                hostname: str = urlsplit(url).hostname
                if filter_url:
                    to_return.append((capture_uuid, hostnode_uuid, hostname, url == filter_url, url))
                else:
                    to_return.append((capture_uuid, hostnode_uuid, hostname, False, url))
            if not unlimited and limit <= 0:
                break
        return len_captures, to_return

    def get_body_hash_domains(self, body_hash: str) -> list[tuple[str, float]]:
        return self.redis.zrevrange(f'bh|{body_hash}', 0, -1, withscores=True)

    def get_body_hash_urls(self, body_hash: str) -> dict[str, list[dict[str, str]]]:
        all_captures: set[str] = self.redis.smembers(f'bh|{body_hash}|captures')
        urls = defaultdict(list)
        for capture_uuid in list(all_captures):
            for entry in self.redis.zrevrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, -1):
                url_uuid, hostnode_uuid, url = entry.split('|', 2)
                urls[url].append({'capture': capture_uuid, 'hostnode': hostnode_uuid, 'urlnode': url_uuid})
        return urls

    # ###### HTTP Headers Hashes ######

    @property
    def http_headers_hashes(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('hhhashes', 0, -1, withscores=True)

    def http_headers_hashes_number_captures(self, hhh: str) -> int:
        return self.redis.scard(f'hhhashes|{hhh}|captures')

    def get_http_headers_hashes_captures(self, hhh: str) -> list[tuple[str, str]]:
        return [uuids.split('|') for uuids in self.redis.smembers(f'hhhashes|{hhh}|captures')]

    def index_http_headers_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_hhhashes', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_hhhashes', crawled_tree.uuid)
        self.logger.debug(f'Indexing http headers hashes for {crawled_tree.uuid} ... ')

        pipeline = self.redis.pipeline()
        already_loaded: set[str] = set()
        already_cleaned_up: set[str] = set()
        is_reindex = False
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if 'hhhash' not in urlnode.features:
                continue
            if urlnode.hhhash in already_loaded:
                # Only add HTTP header Hash once / capture
                continue
            already_loaded.add(urlnode.hhhash)
            if urlnode.hhhash not in already_cleaned_up:
                # We only run this srem once per name for a capture,
                # before adding it for the first time
                to_remove = [key for key in self.redis.sscan_iter(f'hhhashes|{urlnode.hhhash}|captures', f'{crawled_tree.uuid}|*')]
                if to_remove:
                    pipeline.srem(f'hhhashes|{urlnode.hhhash}|captures', * to_remove)
                    is_reindex = True
                    self.logger.debug(f'reindexing http headers hashes for {crawled_tree.uuid} ... ')
                already_cleaned_up.add(urlnode.hhhash)
            pipeline.sadd(f'hhhashes|{urlnode.hhhash}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
            if not is_reindex:
                pipeline.zincrby('hhhashes', 1, urlnode.hhhash)
        pipeline.execute()
        self.logger.debug(f'done with http headers hashes for {crawled_tree.uuid}.')

    # ###### URLs and Domains ######

    def _reindex_urls_domains(self, hostname: str, md5_url: str) -> None:
        # We changed the format of the indexes, so we need to make sure they're re-triggered.
        pipeline = self.redis.pipeline()
        if self.redis.type(f'hostnames|{hostname}|captures') == 'set':  # type: ignore[no-untyped-call]
            pipeline.srem('indexed_urls', *self.redis.smembers(f'hostnames|{hostname}|captures'))
            pipeline.delete(f'hostnames|{hostname}|captures')
        if self.redis.type(f'urls|{md5_url}|captures') == 'set':  # type: ignore[no-untyped-call]
            pipeline.srem('indexed_urls', *self.redis.smembers(f'urls|{md5_url}|captures'))
            pipeline.delete(f'urls|{md5_url}|captures')
        if self.redis.type('hostnames') == 'zset':  # type: ignore[no-untyped-call]
            pipeline.delete('hostnames')
        if self.redis.type('urls') == 'zset':  # type: ignore[no-untyped-call]
            pipeline.delete('urls')
        pipeline.execute()

    @property
    def urls(self) -> set[str]:
        return self.redis.smembers('urls')

    @property
    def hostnames(self) -> set[str]:
        return self.redis.smembers('hostnames')

    def index_url_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_urls', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_urls', crawled_tree.uuid)
        self.logger.debug(f'Indexing URLs for {crawled_tree.uuid} ... ')
        pipeline = self.redis.pipeline()

        # Add the hostnames and urls key in internal indexes set
        internal_index = f'capture_indexes|{crawled_tree.uuid}'
        pipeline.sadd(internal_index, 'hostnames')
        pipeline.sadd(internal_index, 'urls')

        already_indexed_global: set[str] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if not urlnode.hostname or not urlnode.name:
                # no hostname or URL, skip
                continue

            md5_url = hashlib.md5(urlnode.name.encode()).hexdigest()
            self._reindex_urls_domains(urlnode.hostname, md5_url)

            if md5_url not in already_indexed_global:
                # The URL hasn't been indexed in that run yet
                already_indexed_global.add(md5_url)
                pipeline.sadd(f'{internal_index}|urls', md5_url)  # Only used to delete index
                pipeline.sadd(f'{internal_index}|hostnames', urlnode.hostname)  # Only used to delete index
                pipeline.sadd('urls', urlnode.name)
                pipeline.sadd('hostnames', urlnode.hostname)
                pipeline.zadd(f'urls|{md5_url}|captures',
                              mapping={crawled_tree.uuid: crawled_tree.start_time.timestamp()})
                pipeline.zadd(f'hostnames|{urlnode.hostname}|captures',
                              mapping={crawled_tree.uuid: crawled_tree.start_time.timestamp()})

            # Add hostnode UUID in internal index
            pipeline.sadd(f'{internal_index}|urls|{md5_url}', urlnode.uuid)
            pipeline.sadd(f'{internal_index}|hostnames|{urlnode.hostname}', urlnode.uuid)

        pipeline.execute()
        self.logger.debug(f'done with URLs for {crawled_tree.uuid}.')

    def get_captures_url(self, url: str, most_recent_capture: datetime | None = None,
                         oldest_capture: datetime | None= None) -> list[tuple[str, float]]:
        """Get all the captures for a specific URL, on a time interval starting from the most recent one.

        :param url: The URL
        :param most_recent_capture: The capture time of the most recent capture to consider
        :param oldest_capture: The capture time of the oldest capture to consider, defaults to 15 days ago.
        """
        max_score: str | float = most_recent_capture.timestamp() if most_recent_capture else '+Inf'
        min_score: str | float = oldest_capture.timestamp() if oldest_capture else (datetime.now() - timedelta(days=15)).timestamp()
        md5 = hashlib.md5(url.encode()).hexdigest()
        if self.redis.type(f'urls|{md5}|captures') == 'set':  # type: ignore[no-untyped-call]
            # triggers the re-index soon.
            self.redis.srem('indexed_urls', *self.redis.smembers(f'urls|{md5}|captures'))
            return []
        return self.redis.zrevrangebyscore(f'urls|{md5}|captures', max_score, min_score, withscores=True)

    def get_captures_url_count(self, url: str) -> int:
        md5 = hashlib.md5(url.encode()).hexdigest()
        if self.redis.type(f'urls|{md5}|captures') == 'set':  # type: ignore[no-untyped-call]
            # triggers the re-index soon.
            self.redis.srem('indexed_urls', *self.redis.smembers(f'urls|{md5}|captures'))
            return 0
        return self.redis.zcard(f'urls|{md5}|captures')

    def get_captures_hostname(self, hostname: str, most_recent_capture: datetime | None = None,
                              oldest_capture: datetime | None= None) -> list[tuple[str, float]]:
        """Get all the captures for a specific hostname, on a time interval starting from the most recent one.

        :param url: The URL
        :param most_recent_capture: The capture time of the most recent capture to consider
        :param oldest_capture: The capture time of the oldest capture to consider, defaults to 15 days ago.
        """
        max_score: str | float = most_recent_capture.timestamp() if most_recent_capture else '+Inf'
        min_score: str | float = oldest_capture.timestamp() if oldest_capture else (datetime.now() - timedelta(days=15)).timestamp()
        if self.redis.type(f'hostnames|{hostname}|captures') == 'set':  # type: ignore[no-untyped-call]
            # triggers the re-index soon.
            self.redis.srem('indexed_urls', *self.redis.smembers(f'hostnames|{hostname}|captures'))
            return []
        return self.redis.zrevrangebyscore(f'hostnames|{hostname}|captures', max_score, min_score, withscores=True)

    def get_captures_hostname_count(self, hostname: str) -> int:
        if self.redis.type(f'hostnames|{hostname}|captures') == 'set':  # type: ignore[no-untyped-call]
            # triggers the re-index soon.
            self.redis.srem('indexed_urls', *self.redis.smembers(f'hostnames|{hostname}|captures'))
            return 0
        return self.redis.zcard(f'hostnames|{hostname}|captures')

    def get_capture_url_counter(self, capture_uuid: str, url: str) -> int:
        # NOTE: what to do when the capture isn't indexed yet? Raise an exception?
        # For now, return 0
        md5 = hashlib.md5(url.encode()).hexdigest()
        return self.redis.scard(f'capture_indexes|{capture_uuid}|urls|{md5}')

    def get_capture_hostname_counter(self, capture_uuid: str, hostname: str) -> int:
        # NOTE: what to do when the capture isn't indexed yet? Raise an exception?
        # For now, return 0
        return self.redis.scard(f'capture_indexes|{capture_uuid}|hostnames|{hostname}')

    def get_capture_url_nodes(self, capture_uuid: str, url: str) -> set[str]:
        md5 = hashlib.md5(url.encode()).hexdigest()
        if url_nodes := self.redis.smembers(f'capture_indexes|{capture_uuid}|urls|{md5}'):
            return set(url_nodes)
        return set()

    def get_capture_hostname_nodes(self, capture_uuid: str, hostname: str) -> set[str]:
        if url_nodes := self.redis.smembers(f'capture_indexes|{capture_uuid}|hostnames|{hostname}'):
            return set(url_nodes)
        return set()

    # ###### TLDs ######

    @property
    def tlds(self) -> set[str]:
        return self.redis.smembers('tlds')

    def index_tld_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_tlds', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_tlds', crawled_tree.uuid)
        self.logger.debug(f'Indexing TLDs for {crawled_tree.uuid} ... ')
        pipeline = self.redis.pipeline()

        # Add the tlds key in internal indexes set
        internal_index = f'capture_indexes|{crawled_tree.uuid}'
        pipeline.sadd(internal_index, 'tlds')

        already_indexed_global: set[str] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if not hasattr(urlnode, 'known_tld'):
                # No TLD in the node.
                continue
            if urlnode.known_tld not in already_indexed_global:
                # TLD hasn't been indexed in that run yet
                already_indexed_global.add(urlnode.known_tld)
                pipeline.sadd(f'{internal_index}|tlds', urlnode.known_tld)  # Only used to delete index
                pipeline.sadd('tlds', urlnode.known_tld)
                pipeline.zadd(f'tlds|{urlnode.known_tld}|captures',
                              mapping={crawled_tree.uuid: crawled_tree.start_time.timestamp()})

            # Add hostnode UUID in internal index
            pipeline.sadd(f'{internal_index}|tlds|{urlnode.known_tld}', urlnode.uuid)

        pipeline.execute()
        self.logger.debug(f'done with TLDs for {crawled_tree.uuid}.')

    def get_captures_tld(self, tld: str, most_recent_capture: datetime | None = None,
                         oldest_capture: datetime | None= None) -> list[tuple[str, float]]:
        """Get all the captures for a specific TLD, on a time interval starting from the most recent one.

        :param tld: The TLD
        :param most_recent_capture: The capture time of the most recent capture to consider
        :param oldest_capture: The capture time of the oldest capture to consider, defaults to 5 days ago.
        """
        max_score: str | float = most_recent_capture.timestamp() if most_recent_capture else '+Inf'
        min_score: str | float = oldest_capture.timestamp() if oldest_capture else (datetime.now() - timedelta(days=5)).timestamp()
        return self.redis.zrevrangebyscore(f'tlds|{tld}|captures', max_score, min_score, withscores=True)

    def get_capture_tld_counter(self, capture_uuid: str, tld: str) -> int:
        # NOTE: what to do when the capture isn't indexed yet? Raise an exception?
        # For now, return 0
        return self.redis.scard(f'capture_indexes|{capture_uuid}|tlds|{tld}')

    def get_capture_tld_nodes(self, capture_uuid: str, tld: str) -> set[str]:
        if url_nodes := self.redis.smembers(f'capture_indexes|{capture_uuid}|tlds|{tld}'):
            return set(url_nodes)
        return set()

    # ###### favicons ######

    @property
    def favicons(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('favicons', 0, 200, withscores=True)

    def favicon_frequency(self, favicon_sha512: str) -> float | None:
        return self.redis.zscore('favicons', favicon_sha512)

    def favicon_number_captures(self, favicon_sha512: str) -> int:
        return self.redis.scard(f'favicons|{favicon_sha512}|captures')

    def index_favicons_capture(self, capture_uuid: str, capture_dir: Path) -> None:
        if self.redis.sismember('indexed_favicons', capture_uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_favicons', capture_uuid)
        self.logger.debug(f'Indexing favicons for {capture_uuid} ... ')
        pipeline = self.redis.pipeline()
        for favicon_path in sorted(list(capture_dir.glob('*.potential_favicons.ico'))):
            with favicon_path.open('rb') as f:
                favicon = f.read()
                if not favicon:
                    # Empty file, ignore.
                    continue
                sha = hashlib.sha512(favicon).hexdigest()
                if not self.redis.sismember('favicons|{sha}|captures', capture_uuid):
                    # Do not count the same favicon more than once for the same capture
                    pipeline.zincrby('favicons', 1, sha)
                    pipeline.sadd(f'favicons|{sha}|captures', capture_uuid)
                    # There is no easi access to the favicons unless we store them in redis
                    pipeline.set(f'favicons|{sha}', favicon)
        pipeline.execute()

    def get_captures_favicon(self, favicon_sha512: str) -> set[str]:
        return self.redis.smembers(f'favicons|{favicon_sha512}|captures')

    def get_favicon(self, favicon_sha512: str) -> bytes | None:
        return self.redis_bytes.get(f'favicons|{favicon_sha512}')

    # ###### Capture hashes ######

    # This is where we define the indexing for the hashes generated for a whole capture (at most one hash per capture)
    # certpl_html_structure_hash: concatenated list of all the tag names on the page - done on the rendered page

    def _compute_certpl_html_structure_hash(self, html: str) -> str:
        soup = BeautifulSoup(html, "lxml")
        to_hash = "|".join(t.name for t in soup.findAll()).encode()
        return sha256(to_hash).hexdigest()[:32]

    def captures_hashes_types(self) -> set[str]:
        return {'certpl_html_structure_hash'}
    # return self.redis.smembers('capture_hash_types')

    def captures_hashes(self, hash_type: str) -> list[tuple[str, float]]:
        return self.redis.zrevrange(f'capture_hash_types|{hash_type}', 0, 200, withscores=True)

    def hash_frequency(self, hash_type: str, h: str) -> float | None:
        return self.redis.zscore(f'capture_hash_types|{hash_type}', h)

    def hash_number_captures(self, hash_type: str, h: str) -> int:
        return self.redis.scard(f'capture_hash_types|{hash_type}|{h}|captures')

    def index_capture_hashes_types(self, crawled_tree: CrawledTree) -> None:
        capture_uuid = crawled_tree.uuid
        # NOTE: We will have multiple hash types for each captures, we want to make sure
        # to reindex all the captures if there is a new hash type but only index the new
        # captures on the existing hash types
        # hashes = ('certpl_html_structure_hash', )
        for hash_type in self.captures_hashes_types():
            if self.redis.sismember(f'indexed_hash_type|{hash_type}', capture_uuid):
                # Do not reindex
                return
            self.redis.sadd(f'indexed_hash_type|{hash_type}', capture_uuid)

            if hash_type == 'certpl_html_structure_hash':
                # we must have a rendered HTML for this hash to be relevant.
                if (not hasattr(crawled_tree.root_hartree.rendered_node, 'rendered_html')
                        or not crawled_tree.root_hartree.rendered_node.rendered_html):
                    continue
                # we have a rendered HTML, compute the hash
                hash_to_index = self._compute_certpl_html_structure_hash(crawled_tree.root_hartree.rendered_node.rendered_html)
            else:
                self.logger.warning(f'Unknown hash type: {hash_type}')
                continue

            if not hash_to_index:
                self.logger.info(f'No hash to index for {hash_type} in {capture_uuid} ... ')
                continue

            if self.redis.sismember(f'capture_hash_types|{hash_type}|{hash_to_index}|captures', capture_uuid):
                # Already counted this specific identifier for this capture
                continue
            self.logger.debug(f'Indexing hash {hash_type} for {capture_uuid} ... ')
            pipeline = self.redis.pipeline()
            pipeline.hset(f'capture_hash_types|{capture_uuid}', hash_type, hash_to_index)
            pipeline.sadd(f'capture_hash_types|{hash_type}|{hash_to_index}|captures', capture_uuid)
            pipeline.zincrby(f'capture_hash_types|{hash_type}', 1, hash_to_index)
            pipeline.execute()

    def get_hashes_types_capture(self, capture_uuid: str) -> dict[str, str]:
        return self.redis.hgetall(f'capture_hash_types|{capture_uuid}')

    def get_captures_hash_type(self, hash_type: str, h: str) -> set[str]:
        return self.redis.smembers(f'capture_hash_types|{hash_type}|{h}|captures')

    # ###### identifiers ######

    def identifiers_types(self) -> set[str]:
        return self.redis.smembers('identifiers_types')

    def identifiers(self, identifier_type: str) -> list[tuple[str, float]]:
        return self.redis.zrevrange(f'identifiers|{identifier_type}', 0, 200, withscores=True)

    def identifier_frequency(self, identifier_type: str, identifier: str) -> float | None:
        return self.redis.zscore(f'identifiers|{identifier_type}', identifier)

    def identifier_number_captures(self, identifier_type: str, identifier: str) -> int:
        return self.redis.scard(f'identifiers|{identifier_type}|{identifier}|captures')

    def index_identifiers_capture(self, crawled_tree: CrawledTree) -> None:
        capture_uuid = crawled_tree.uuid
        if self.redis.sismember('indexed_identifiers', capture_uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_identifiers', capture_uuid)
        if (not hasattr(crawled_tree.root_hartree.rendered_node, 'identifiers')
                or not crawled_tree.root_hartree.rendered_node.identifiers):
            return
        pipeline = self.redis.pipeline()
        # We have multiple identifiers types, this is the difference with the other indexes
        for identifier_type, id_values in crawled_tree.root_hartree.rendered_node.identifiers.items():
            pipeline.sadd('identifiers_types', identifier_type)  # no-op if already there
            if self.redis.sismember(f'indexed_identifiers|{identifier_type}|captures', capture_uuid):
                # Do not reindex the same identifier type for the same capture
                continue
            pipeline.sadd(f'indexed_identifiers|{identifier_type}|captures', capture_uuid)
            self.logger.debug(f'Indexing identifiers {identifier_type} for {capture_uuid} ... ')
            for identifier in id_values:
                if self.redis.sismember(f'identifiers|{identifier_type}|{identifier}|captures', capture_uuid):
                    # Already counted this specific identifier for this capture
                    continue
                pipeline.sadd(f'identifiers|{capture_uuid}', identifier_type)
                pipeline.sadd(f'identifiers|{capture_uuid}|{identifier_type}', identifier)
                pipeline.sadd(f'identifiers|{identifier_type}|{identifier}|captures', capture_uuid)
                pipeline.zincrby(f'identifiers|{identifier_type}', 1, identifier)
        pipeline.execute()

    def get_identifiers_capture(self, capture_uuid: str) -> dict[str, set[str]]:
        to_return = {}
        for identifier_type in self.redis.smembers(f'identifiers|{capture_uuid}'):
            to_return[identifier_type] = self.redis.smembers(f'identifiers|{capture_uuid}|{identifier_type}')
        return to_return

    def get_captures_identifier(self, identifier_type: str, identifier: str) -> set[str]:
        return self.redis.smembers(f'identifiers|{identifier_type}|{identifier}|captures')

    # ###### favicons probabilistic hashes ######

    def favicon_probabilistic_frequency(self, algorithm: str, phash: str) -> float | None:
        return self.redis.zscore(f'favicons|{algorithm}', phash)

    def index_favicons_probabilistic(self, capture_uuid: str, favicons: BytesIO, algorithm: str) -> None:
        # FIXME: this method isnt used anymore
        if self.redis.sismember(f'indexed_favicons_probabilistic|{algorithm}', capture_uuid):
            # Do not reindex
            return
        self.redis.sadd(f'indexed_favicons_probabilistic|{algorithm}', capture_uuid)
        pipeline = self.redis.pipeline()
        with ZipFile(favicons, 'r') as myzip:
            for name in myzip.namelist():
                if not name.endswith('.ico'):
                    continue
                favicon = myzip.read(name)
                if not favicon:
                    # Empty file, ignore.
                    continue
                sha = hashlib.sha512(favicon).hexdigest()
                if algorithm == 'mmh3-shodan':
                    # Shodan uses a weird technique:
                    # 1. encodes the image to base64, with newlines every 76 characters (as per RFC 2045)
                    # 2. hashes the base64 string with mmh3
                    b64 = base64.encodebytes(favicon)
                    h = str(mmh3.hash(b64))
                else:
                    raise NotImplementedError(f'Unknown algorithm: {algorithm}')
                pipeline.zincrby(f'favicons|{algorithm}', 1, h)
                # All captures with this hash for this algorithm
                pipeline.sadd(f'favicons|{algorithm}|{h}|captures', capture_uuid)
                # All hashes with this hash for this algorithm
                pipeline.sadd(f'favicons|{algorithm}|{h}|favicons', sha)
                # reverse lookup to get probabilistic hashes related to a specific favicon
                pipeline.sadd(f'favicons|{algorithm}|{sha}', h)
        pipeline.execute()

    def get_hashes_favicon_probablistic(self, algorithm: str, phash: str) -> set[str]:
        '''All the favicon sha512 for this probabilistic hash for this algorithm'''
        return self.redis.smembers(f'favicons|{algorithm}|{phash}|favicons')

    def get_probabilistic_hashes_favicon(self, algorithm: str, favicon_sha512: str) -> set[str]:
        '''All the probabilistic hashes for this favicon SHA512 for this algorithm'''''
        return self.redis.smembers(f'favicons|{algorithm}|{favicon_sha512}')

    def get_captures_favicon_probablistic(self, algorithm: str, phash: str) -> set[str]:
        '''All the captures with this probabilistic hash for this algorithm'''
        return self.redis.smembers(f'favicons|{algorithm}|{phash}|captures')

    # ###### Categories ######

    @property
    def categories(self) -> set[str]:
        return self.redis.smembers('categories')

    def index_categories_capture(self, capture_uuid: str, capture_dir: Path) -> None:
        if self.redis.sismember('indexed_categories', capture_uuid):
            # do not reindex
            return
        # Make sure we don't reindex
        self.redis.sadd('indexed_categories', capture_uuid)

        categ_file = capture_dir / 'categories'
        if categ_file.exists():
            with categ_file.open('r') as f:
                capture_categories = [c.strip() for c in f.readlines()]
        else:
            return

        added_in_existing_categories = set()
        pipeline = self.redis.pipeline()
        for c in self.categories:
            if c in capture_categories:
                pipeline.sadd(c, capture_uuid)
                added_in_existing_categories.add(c)
            else:
                # the capture is not in that category, srem is as cheap as exists if not in the set
                pipeline.srem(c, capture_uuid)
        # Handle the new categories
        for new_c in set(capture_categories) - added_in_existing_categories:
            pipeline.sadd(new_c, capture_uuid)
            pipeline.sadd('categories', new_c)
        pipeline.execute()

    def get_captures_category(self, category: str) -> set[str]:
        return self.redis.smembers(category)

    def capture_in_category(self, capture_uuid: str, category: str) -> bool:
        return self.redis.sismember(category, capture_uuid)

    def reindex_categories_capture(self, capture_uuid: str) -> None:
        self.redis.srem('indexed_categories', capture_uuid)
