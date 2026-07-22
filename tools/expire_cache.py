#!/usr/bin/env python3

from datetime import timedelta

from redis import Redis

from lookyloo.default import get_socket_path, get_config
from lookyloo import Lookyloo

redis_cache = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

time_delta_on_index = timedelta(days=get_config('generic', 'archive'))

lookyloo = Lookyloo()

for cc in lookyloo.sorted_capture_cache(cached_captures_only=False):
    redis_cache.expire(str(cc.capture_dir), int(time_delta_on_index.total_seconds()) * 2)


for uuid, capture_dir in redis_cache.hscan_iter('lookup_dirs_archived'):
    redis_cache.expire(capture_dir, int(time_delta_on_index.total_seconds()) * 2)
