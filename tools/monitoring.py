#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys

from typing import List, Tuple

from redis import Redis
from redis.exceptions import ConnectionError

from lookyloo.helpers import get_config, get_socket_path, splash_status
from lookyloo.abstractmanager import AbstractManager


class Monitoring():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_cache: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.redis_indexing: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    @property
    def backend_status(self):
        socket_path_cache = get_socket_path('cache')
        socket_path_index = get_socket_path('indexing')
        backend_up = True
        if not os.path.exists(socket_path_cache):
            print(f'Socket path for the cache redis DB does not exists ({socket_path_cache}).')
            backend_up = False
        if not os.path.exists(socket_path_index):
            print(f'Socket path for the indexing redis DB does not exists ({socket_path_index}).')
            backend_up = False
        if backend_up:
            try:
                cache_reachable = True if self.redis_cache.ping() else False
                if not cache_reachable:
                    print('Unable to ping the redis cache db.')
                    backend_up = False
            except ConnectionError:
                print('Unable to connect to the redis cache db.')
                backend_up = False
            try:
                indexing_reachable = True if self.redis_indexing.ping() else False
                if not indexing_reachable:
                    print('Unable to ping the redis indexing db.')
                    backend_up = False
            except ConnectionError:
                print('Unable to connect to the redis indexing db.')
                backend_up = False

        return backend_up

    @property
    def queues(self):
        return self.redis_cache.zrevrangebyscore('queues', 'Inf', '-Inf', withscores=True)

    @property
    def ongoing_captures(self):
        captures_uuid: List[Tuple[str, float]] = self.redis_cache.zrevrangebyscore('to_capture', 'Inf', '-Inf', withscores=True)
        if not captures_uuid:
            return []
        to_return = []
        for uuid, rank in captures_uuid:
            capture_params = self.redis_cache.hgetall(uuid)
            if capture_params:
                to_return.append((uuid, rank, capture_params))

        return to_return


if __name__ == '__main__':

    status, message = splash_status()
    if status:
        print(message)
    else:
        print('Splash is down: ', message)

    m = Monitoring()
    backend_up = m.backend_status
    if not backend_up:
        print('Backend not up, breaking.')
        sys.exit()

    print('Services currently running:')
    running = AbstractManager.is_running()
    for service, number in running:
        print(service, f'({int(number)} service(s))')

    print('Current queues:')
    for q, priority in m.queues:
        print(q, f'Priority: {int(priority)}')
    # ------------------
    print('Captures details:')
    captures = m.ongoing_captures
    print('Queue length', len(captures))
    for uuid, rank, d in captures:
        print(uuid, f'Rank: {int(rank)}')
        print(json.dumps(d, indent=2))
