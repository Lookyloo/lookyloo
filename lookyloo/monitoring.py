#!/usr/bin/env python3

from __future__ import annotations

import logging
import os

from datetime import date
from typing import Any

from redis.exceptions import ConnectionError

from lacuscore import CaptureStatus as CaptureStatusCore
from pylacus import PyLacus, CaptureStatus as CaptureStatusPy

from lookyloo import Lookyloo
from lookyloo.helpers import get_indexing
from lookyloo.default import get_socket_path, AbstractManager, get_config


class Monitoring():

    def __init__(self, lookyloo: Lookyloo) -> None:
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(get_config('generic', 'loglevel'))
        self.lookyloo = lookyloo

    def visitors_stats(self, day: date | None=None) -> dict[str, int | list[dict[str, Any]]]:
        '''All the hits on lookyloo land in there, not just the ones submitting something
        The main usage is to generate a list of UAs used later on the web interface (if enabled).'''
        if not day:
            day = date.today()
        day_key = f'user_agents|{day.isoformat()}'
        to_return: dict[str, Any] = {'entries': self.lookyloo.redis.zcard(day_key), 'visitors': []}
        per_ip: dict[str, dict[str, Any]] = {}
        for entry, hits in self.lookyloo.redis.zrevrangebyscore(day_key, '+Inf', '-Inf', withscores=True):
            ip, ua = entry.split('|', 1)
            # initialize key ip in per_ip with the template dict
            item = per_ip.setdefault(ip, {'ip': ip, 'hits': 0, 'user_agents': []})
            item['hits'] += int(hits)
            item['user_agents'].append(ua)
        to_return['visitors'] = sorted(per_ip.values(), key=lambda i: i['hits'], reverse=True)
        return to_return

    @property
    def lacuses_status(self) -> dict[str, tuple[bool, str]]:
        to_return = {}
        for name, connector in self.lookyloo.lacus.items():
            if isinstance(connector, PyLacus):
                to_return[name] = (connector.is_up, connector.root_url)
            else:
                to_return[name] = (True, 'local')
        return to_return

    @property
    def backend_status(self) -> tuple[bool, list[str]]:
        socket_path_cache = get_socket_path('cache')
        socket_path_index = get_socket_path('indexing')
        backend_up = True
        errors = []
        if not os.path.exists(socket_path_cache):
            errors.append(f'Socket path for the [blue]cache[/blue] redis DB [red]does not exists[/red] ({socket_path_cache}).')
            backend_up = False
        if not os.path.exists(socket_path_index):
            errors.append(f'Socket path for the [blue]indexing[/blue] redis DB [red]does not exists[/red] ({socket_path_index}).')
            backend_up = False
        if backend_up:
            try:
                cache_reachable = True if self.lookyloo.redis.ping() else False
                if not cache_reachable:
                    errors.append('Unable to ping the redis cache db.')
                    backend_up = False
            except ConnectionError:
                errors.append('Unable to connect to the redis cache db.')
                backend_up = False

            try:
                indexing_reachable = True if get_indexing().redis.ping() else False
                if not indexing_reachable:
                    errors.append('Unable to ping the redis indexing db.')
                    backend_up = False
            except ConnectionError:
                errors.append('Unable to connect to the redis indexing db.')
                backend_up = False

            if get_config('generic', 'index_everything'):
                try:
                    full_indexing_reachable = True if get_indexing(full=True).redis.ping() else False
                    if not full_indexing_reachable:
                        errors.append('Unable to ping the full indexing db.')
                        backend_up = False
                except ConnectionError:
                    errors.append('Unable to connect to the full indexing db.')
                    backend_up = False

        return backend_up, errors

    @property
    def services(self) -> list[tuple[str, float, set[str], set[str]]]:
        return AbstractManager.is_running()

    @property
    def queues(self) -> list[tuple[str, float]]:
        return self.lookyloo.redis.zrevrangebyscore('queues', 'Inf', '-Inf', withscores=True)

    @property
    def ongoing_captures(self) -> list[tuple[str, float, dict[str, Any]]]:
        to_return = []
        for uuid, rank in self.lookyloo.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf', withscores=True):
            capture_params = self.lookyloo.redis.hgetall(uuid)
            if 'document' in capture_params:
                # do not display that
                capture_params['document'] = '<b64 encoded document>'
            if capture_params:
                to_return.append((uuid, rank, capture_params))

        return to_return

    @property
    def tree_cache(self) -> dict[str, str]:
        to_return = {}
        for pid_name, value in self.lookyloo.redis.hgetall('tree_cache').items():
            pid, name = pid_name.split('|', 1)
            try:
                os.kill(int(pid), 0)
            except OSError:
                self.lookyloo.redis.hdel('tree_cache', pid_name)
                continue
            to_return[pid_name] = value
        return to_return

    @property
    def lacuses_status_details(self) -> dict[str, dict[str, Any]]:
        to_return = {}
        for name, connector in self.lookyloo.lacus.items():
            if not isinstance(connector, PyLacus):
                continue
            details = {}
            details['is_busy'] = connector.is_busy()
            status = connector.status()
            details['max_concurrent_captures'] = status['max_concurrent_captures']
            details['ongoing_captures'] = status['ongoing_captures']
            details['enqueued_captures'] = status['enqueued_captures']
            to_return[name] = details
        return to_return

    @property
    def captures_status(self) -> dict[str, Any]:
        '''Captures being captured (ongoing) and waiting (to_capture, by priority).'''
        captures = []
        queued_total = 0
        ongoing_total = 0
        for capture_uuid, priority in self.lookyloo.redis.zrevrangebyscore('to_capture', '+Inf', '-Inf', withscores=True):
            url, document_name = self.lookyloo.redis.hmget(capture_uuid, ['url', 'document_name'])
            if mgmt := self.lookyloo.redis.get(f'{capture_uuid}_mgmt'):
                source, authenticated, user = mgmt.split('|', 2)
            else:
                self.logger.warning(f'Missing management key for capture {capture_uuid}')
                continue
            queued_total += 1
            to_add = {'uuid': capture_uuid, 'priority': int(priority), 'url': url or document_name,
                      'source': source, 'authenticated': authenticated == 'True', 'user': user,
                      'state': 'Queued'}
            if self.lookyloo.get_capture_status(capture_uuid) in (CaptureStatusCore.ONGOING, CaptureStatusPy.ONGOING):
                to_add['state'] = 'Capturing'
                ongoing_total += 1
            captures.append(to_add)
        return {'captures': captures, 'ongoing_total': ongoing_total, 'queued_total': queued_total}
