#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import logging
# import re
from io import BytesIO
from collections import defaultdict
from typing import Iterable
from urllib.parse import urlsplit
from zipfile import ZipFile

import mmh3

from bs4 import BeautifulSoup
from hashlib import sha256

from har2tree import CrawledTree
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_socket_path, get_config
# from .helpers import get_public_suffix_list


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

    @property
    def can_index(self) -> bool:
        return bool(self.redis.set('ongoing_indexing', 1, ex=3600, nx=True))

    def indexing_done(self) -> None:
        self.redis.delete('ongoing_indexing')

    def force_reindex(self, capture_uuid: str) -> None:
        p = self.redis.pipeline()
        p.srem('indexed_urls', capture_uuid)
        p.srem('indexed_body_hashes', capture_uuid)
        p.srem('indexed_cookies', capture_uuid)
        p.srem('indexed_hhhashes', capture_uuid)
        p.srem('indexed_favicons', capture_uuid)
        p.srem('indexed_identifiers', capture_uuid)
        for identifier_type in self.identifiers_types():
            p.srem(f'indexed_identifiers|{identifier_type}|captures', capture_uuid)
        for hash_type in self.captures_hashes_types():
            p.srem(f'indexed_hash_type|{hash_type}', capture_uuid)
        p.execute()

    def capture_indexed(self, capture_uuid: str) -> tuple[bool, bool, bool, bool, bool, bool, bool]:
        p = self.redis.pipeline()
        p.sismember('indexed_urls', capture_uuid)
        p.sismember('indexed_body_hashes', capture_uuid)
        p.sismember('indexed_cookies', capture_uuid)
        p.sismember('indexed_hhhashes', capture_uuid)
        p.sismember('indexed_favicons', capture_uuid)
        p.sismember('indexed_identifiers', capture_uuid)
        # We also need to check if the hash_type are all indexed for this capture
        hash_types_indexed = all(self.redis.sismember(f'indexed_hash_type|{hash_type}', capture_uuid) for hash_type in self.captures_hashes_types())
        to_return: list[bool] = p.execute()
        to_return.append(hash_types_indexed)
        # This call for sure returns a tuple of 7 booleans
        return tuple(to_return)  # type: ignore[return-value]

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
                # Only add cookie name once / capture
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

    @property
    def urls(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('urls', 0, 200, withscores=True)

    @property
    def hostnames(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('hostnames', 0, 200, withscores=True)

    def index_url_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_urls', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_urls', crawled_tree.uuid)
        self.logger.debug(f'Indexing URLs for {crawled_tree.uuid} ... ')
        pipeline = self.redis.pipeline()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if not urlnode.hostname or not urlnode.name:
                continue
            if not self.redis.sismember(f'hostnames|{urlnode.hostname}|captures', crawled_tree.uuid):
                pipeline.zincrby('hostnames', 1, urlnode.hostname)
                pipeline.zincrby('urls', 1, urlnode.name)
                pipeline.sadd(f'hostnames|{urlnode.hostname}|captures', crawled_tree.uuid)
                # set of all captures with this URL
                # We need to make sure the keys in redis aren't too long.
                md5 = hashlib.md5(urlnode.name.encode()).hexdigest()
                pipeline.sadd(f'urls|{md5}|captures', crawled_tree.uuid)
        pipeline.execute()
        self.logger.debug(f'done with URLs for {crawled_tree.uuid}.')

    def get_captures_url(self, url: str) -> set[str]:
        md5 = hashlib.md5(url.encode()).hexdigest()
        return self.redis.smembers(f'urls|{md5}|captures')

    def get_captures_hostname(self, hostname: str) -> set[str]:
        return self.redis.smembers(f'hostnames|{hostname}|captures')

    # ###### favicons ######

    @property
    def favicons(self) -> list[tuple[str, float]]:
        return self.redis.zrevrange('favicons', 0, 200, withscores=True)

    def favicon_frequency(self, favicon_sha512: str) -> float | None:
        return self.redis.zscore('favicons', favicon_sha512)

    def favicon_number_captures(self, favicon_sha512: str) -> int:
        return self.redis.scard(f'favicons|{favicon_sha512}|captures')

    def index_favicons_capture(self, capture_uuid: str, favicons: BytesIO) -> None:
        if self.redis.sismember('indexed_favicons', capture_uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_favicons', capture_uuid)
        self.logger.debug(f'Indexing favicons for {capture_uuid} ... ')
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
    def categories(self) -> list[tuple[str, int]]:
        return [(c, int(score))
                for c, score in self.redis.zrevrange('categories', 0, 200, withscores=True)]

    def index_categories_capture(self, capture_uuid: str, categories: Iterable[str]) -> None:
        if not categories:
            return
        if self.redis.sismember('indexed_categories', capture_uuid):
            # do not reindex
            return
        self.redis.sadd('indexed_categories', capture_uuid)
        if not categories:
            return
        pipeline = self.redis.pipeline()
        for category in categories:
            pipeline.zincrby('categories', 1, category)
            pipeline.sadd(category, capture_uuid)
        pipeline.execute()

    def get_captures_category(self, category: str) -> set[str]:
        return self.redis.smembers(category)
