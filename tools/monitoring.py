#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging

from redis import Redis

from lookyloo.helpers import get_config, get_socket_path, splash_status


class Monitoring():

    def __init__(self) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))

        self.redis_cache: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.redis_indexing: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    @property
    def queues(self):
        return self.redis_cache.zrevrangebyscore('queues', 'Inf', '-Inf', withscores=True)

    @property
    def ongoing_captures(self):
        captures_uuid = self.redis_cache.zrevrangebyscore('to_capture', 'Inf', '-Inf', withscores=True)
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
    print('Current queues:')
    for q in m.queues:
        print(q)
    # ------------------
    print('Captures details:')
    captures = m.ongoing_captures
    print('Queue length', len(captures))
    for uuid, rank, d in captures:
        print(uuid, rank)
        print(json.dumps(d, indent=2))
