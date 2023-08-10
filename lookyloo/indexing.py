#!/usr/bin/env python3

import hashlib
import logging
# import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from har2tree import CrawledTree
from redis import ConnectionPool, Redis
from redis.connection import UnixDomainSocketConnection

from .default import get_socket_path, get_config
# from .helpers import get_public_suffix_list


class Indexing():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.redis_pool: ConnectionPool = ConnectionPool(connection_class=UnixDomainSocketConnection,
                                                         path=get_socket_path('indexing'), decode_responses=True)

    def clear_indexes(self):
        self.redis.flushdb()

    @property
    def redis(self):
        return Redis(connection_pool=self.redis_pool)

    def new_internal_uuids(self, crawled_tree: CrawledTree) -> None:
        # only trigger this method if the capture was already indexed.
        if self.redis.sismember('indexed_cookies', crawled_tree.uuid):
            self.logger.debug(f'Cookies index: update internal UUIDs for {crawled_tree.uuid}')
            self._reindex_cookies_capture(crawled_tree)
        if self.redis.sismember('indexed_body_hashes', crawled_tree.uuid):
            self.logger.debug(f'Body hashes index: update internal UUIDs for {crawled_tree.uuid}')
            self._reindex_body_hashes_capture(crawled_tree)
        if self.redis.sismember('indexed_hhhashes', crawled_tree.uuid):
            self.logger.debug(f'HTTP Headers hashes index: update internal UUIDs for {crawled_tree.uuid}')
            self._reindex_http_headers_hashes_capture(crawled_tree)

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
        return [uuids.split('|') for uuids in self.redis.smembers(f'cn|{cookie_name}|captures')]

    def _reindex_cookies_capture(self, crawled_tree: CrawledTree) -> None:
        pipeline = self.redis.pipeline()
        already_loaded: Set[Tuple[str, str]] = set()
        already_cleaned_up: Set[str] = set()
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
                    already_cleaned_up.add(name)
                pipeline.sadd(f'cn|{name}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
        pipeline.execute()

    def index_cookies_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_cookies', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_cookies', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        already_loaded: Set[Tuple[str, str]] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if 'cookies_received' not in urlnode.features:
                continue
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

    """
    # Not used anywhere?
    def aggregate_domain_cookies(self):
        psl = get_public_suffix_list()
        pipeline = self.redis.pipeline()
        for cn, cn_freq in self.cookies_names:
            for domain, d_freq in self.get_cookie_domains(cn):
                tld = psl.publicsuffix(domain)
                main_domain_part = re.sub(f'.{tld}$', '', domain).split('.')[-1]
                pipeline.zincrby('aggregate_domains_cn', cn_freq, f'{main_domain_part}|{cn}')
                pipeline.zincrby('aggregate_cn_domains', d_freq, f'{cn}|{main_domain_part}')
        pipeline.execute()
        aggregate_domains_cn: List[Tuple[str, float]] = self.redis.zrevrange('aggregate_domains_cn', 0, -1, withscores=True)
        aggregate_cn_domains: List[Tuple[str, float]] = self.redis.zrevrange('aggregate_cn_domains', 0, -1, withscores=True)
        self.redis.delete('aggregate_domains_cn')
        self.redis.delete('aggregate_cn_domains')
        return {'domains': aggregate_domains_cn, 'cookies': aggregate_cn_domains}
    """

    # ###### Body hashes ######

    @property
    def ressources(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('body_hashes', 0, 200, withscores=True)

    def ressources_number_domains(self, h: str) -> int:
        return self.redis.zcard(f'bh|{h}')

    def body_hash_fequency(self, body_hash: str) -> Dict[str, int]:
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

    def _reindex_body_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        # if the capture is regenerated, the hostnodes/urlnodes UUIDs are changed
        cleaned_up_hashes: Set[str] = set()
        pipeline = self.redis.pipeline()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            for h in urlnode.resources_hashes:
                if h not in cleaned_up_hashes:
                    # Delete the hash for that capture the first time we see it.
                    pipeline.delete(f'bh|{h}|captures|{crawled_tree.uuid}')
                    cleaned_up_hashes.add(h)
                pipeline.zincrby(f'bh|{h}|captures|{crawled_tree.uuid}', 1,
                                 f'{urlnode.uuid}|{urlnode.hostnode_uuid}|{urlnode.name}')
        pipeline.execute()

    def index_body_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_body_hashes', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_body_hashes', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            for h in urlnode.resources_hashes:
                pipeline.zincrby('body_hashes', 1, h)
                pipeline.zincrby(f'bh|{h}', 1, urlnode.hostname)
                # set of all captures with this hash
                pipeline.sadd(f'bh|{h}|captures', crawled_tree.uuid)
                # ZSet of all urlnode_UUIDs|full_url
                pipeline.zincrby(f'bh|{h}|captures|{crawled_tree.uuid}', 1,
                                 f'{urlnode.uuid}|{urlnode.hostnode_uuid}|{urlnode.name}')
        pipeline.execute()

    def get_hash_uuids(self, body_hash: str) -> Tuple[str, str, str]:
        """Use that to get a reference allowing to fetch a resource from one of the capture."""
        capture_uuid: str = self.redis.srandmember(f'bh|{body_hash}|captures')
        entry = self.redis.zrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, 1)[0]
        urlnode_uuid, hostnode_uuid, url = entry.split('|', 2)
        return capture_uuid, urlnode_uuid, hostnode_uuid

    def get_body_hash_captures(self, body_hash: str, filter_url: Optional[str]=None,
                               filter_capture_uuid: Optional[str]=None,
                               limit: int=20,
                               prefered_uuids: Set[str]=set()) -> Tuple[int, List[Tuple[str, str, str, bool]]]:
        '''Get the captures matching the hash.
        :param filter_url: URL of the hash we're searching for
        :param filter_capture_uuid: UUID of the capture the hash was found in
        :param limit: Max matching captures to return
        :param prefered_uuids: UUID cached right now, so we don't rebuild trees.
        '''
        to_return: List[Tuple[str, str, str, bool]] = []
        all_captures: Set[str] = self.redis.smembers(f'bh|{body_hash}|captures')
        len_captures = len(all_captures)
        for capture_uuid in list(all_captures)[:limit]:
            if capture_uuid == filter_capture_uuid:
                # Used to skip hits in current capture
                len_captures -= 1
                continue
            if prefered_uuids and capture_uuid not in prefered_uuids:
                continue
            for entry in self.redis.zrevrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, -1):
                url_uuid, hostnode_uuid, url = entry.split('|', 2)
                hostname: str = urlsplit(url).hostname
                if filter_url:
                    to_return.append((capture_uuid, hostnode_uuid, hostname, url == filter_url))
                else:
                    to_return.append((capture_uuid, hostnode_uuid, hostname, False))
        return len_captures, to_return

    def get_body_hash_domains(self, body_hash: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'bh|{body_hash}', 0, -1, withscores=True)

    def get_body_hash_urls(self, body_hash: str) -> Dict[str, List[Dict[str, str]]]:
        all_captures: Set[str] = self.redis.smembers(f'bh|{body_hash}|captures')
        urls = defaultdict(list)
        for capture_uuid in list(all_captures):
            for entry in self.redis.zrevrange(f'bh|{body_hash}|captures|{capture_uuid}', 0, -1):
                url_uuid, hostnode_uuid, url = entry.split('|', 2)
                urls[url].append({'capture': capture_uuid, 'hostnode': hostnode_uuid, 'urlnode': url_uuid})
        return urls

    # ###### HTTP Headers Hashes ######

    @property
    def http_headers_hashes(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('hhhashes', 0, -1, withscores=True)

    def http_headers_hashes_number_captures(self, hhh: str) -> int:
        return self.redis.scard(f'hhhashes|{hhh}|captures')

    def get_http_headers_hashes_captures(self, hhh: str) -> List[Tuple[str, str]]:
        return [uuids.split('|') for uuids in self.redis.smembers(f'hhhashes|{hhh}|captures')]

    def _reindex_http_headers_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        pipeline = self.redis.pipeline()
        already_loaded: Set[str] = set()
        already_cleaned_up: Set[str] = set()
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
                already_cleaned_up.add(urlnode.hhhash)
            pipeline.sadd(f'hhhashes|{urlnode.hhhash}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
        pipeline.execute()

    def index_http_headers_hashes_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_hhhashes', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_hhhashes', crawled_tree.uuid)

        pipeline = self.redis.pipeline()
        already_loaded: Set[str] = set()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if 'hhhash' not in urlnode.features:
                continue
            if urlnode.hhhash in already_loaded:
                # Only add cookie name once / capture
                continue
            already_loaded.add(urlnode.hhhash)
            pipeline.zincrby('hhhashes', 1, urlnode.hhhash)
            pipeline.sadd(f'hhhashes|{urlnode.hhhash}|captures', f'{crawled_tree.uuid}|{urlnode.uuid}')
        pipeline.execute()

    # ###### URLs and Domains ######

    @property
    def urls(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('urls', 0, 200, withscores=True)

    @property
    def hostnames(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('hostnames', 0, 200, withscores=True)

    def index_url_capture(self, crawled_tree: CrawledTree) -> None:
        if self.redis.sismember('indexed_urls', crawled_tree.uuid):
            # Do not reindex
            return
        self.redis.sadd('indexed_urls', crawled_tree.uuid)
        pipeline = self.redis.pipeline()
        for urlnode in crawled_tree.root_hartree.url_tree.traverse():
            if not urlnode.hostname or not urlnode.name:
                continue
            pipeline.zincrby('hostnames', 1, urlnode.hostname)
            pipeline.sadd(f'hostnames|{urlnode.hostname}|captures', crawled_tree.uuid)
            pipeline.zincrby('urls', 1, urlnode.name)
            # set of all captures with this URL
            # We need to make sure the keys in redis aren't too long.
            md5 = hashlib.md5(urlnode.name.encode()).hexdigest()
            pipeline.sadd(f'urls|{md5}|captures', crawled_tree.uuid)
        pipeline.execute()

    def get_captures_url(self, url: str) -> Set[str]:
        md5 = hashlib.md5(url.encode()).hexdigest()
        return self.redis.smembers(f'urls|{md5}|captures')

    def get_captures_hostname(self, hostname: str) -> Set[str]:
        return self.redis.smembers(f'hostnames|{hostname}|captures')

    # ###### Categories ######

    @property
    def categories(self) -> List[Tuple[str, int]]:
        return [(c, int(score))
                for c, score in self.redis.zrevrange('categories', 0, 200, withscores=True)]

    def index_categories_capture(self, capture_uuid: str, categories: Iterable[str]):
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

    def get_captures_category(self, category: str) -> Set[str]:
        return self.redis.smembers(category)
