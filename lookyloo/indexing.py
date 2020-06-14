#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Set, Tuple, List, Optional, Dict, Any

from redis import Redis

from .helpers import get_socket_path
from .lookyloo import Lookyloo


class Indexing():

    def __init__(self) -> None:
        self.lookyloo = Lookyloo()
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    @property
    def cookies_names(self) -> List[Tuple[str, float]]:
        return self.redis.zrevrange('cookies_names', 0, -1, withscores=True)

    def cookies_names_number_domains(self, cookie_name: str) -> int:
        return self.redis.zcard(f'cn|{cookie_name}')

    def cookies_names_domains_values(self, cookie_name: str, domain: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}|{domain}', 0, -1, withscores=True)

    def get_cookie_domains(self, cookie_name: str) -> List[Tuple[str, float]]:
        return self.redis.zrevrange(f'cn|{cookie_name}', 0, -1, withscores=True)

    def get_capture_cache(self, capture_uuid: str) -> Optional[Dict[str, Any]]:
        capture_dir = self.lookyloo.lookup_capture_dir(capture_uuid)
        if capture_dir:
            return self.lookyloo.capture_cache(capture_dir)
        return {}

    def get_cookies_names_captures(self, cookie_name: str) -> List[Tuple[str, str]]:
        return [uuids.split('|')for uuids in self.redis.smembers(f'cn|{cookie_name}|captures')]

    def index_cookies(self) -> None:
        for capture_dir in self.lookyloo.capture_dirs:
            print(f'Processing {capture_dir}')
            try:
                crawled_tree = self.lookyloo.get_crawled_tree(capture_dir)
            except Exception as e:
                print(e)
                continue
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

                        # pipeline.zincrby('lookyloo_cookies_index_values', 1, value)
                        # pipeline.zincrby(value, 1, name)
            pipeline.execute()
