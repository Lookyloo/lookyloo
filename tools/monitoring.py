#!/usr/bin/env python3

from __future__ import annotations

import os
import sys

from typing import Any

from redis import Redis
from redis.exceptions import ConnectionError
from rich.console import Console
from rich.padding import Padding

from pylacus import PyLacus

from lookyloo.default import get_socket_path, AbstractManager, get_config

# NOTE: run with watch:
#   watch --color tools/monitoring.py

console = Console(color_system="256")


class Monitoring():

    lacus: PyLacus | None = None

    def __init__(self) -> None:
        self.redis_cache: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)  # type: ignore[type-arg]
        self.redis_indexing: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)  # type: ignore[type-arg]
        # try to connect to a remote lacus if lookyloo is configured this way
        if remote_lacus_config := get_config('generic', 'remote_lacus'):
            if remote_lacus_config.get('enable'):
                remote_lacus_url = remote_lacus_config.get('url')
                self.lacus = PyLacus(remote_lacus_url)
                if not self.lacus.is_up:
                    self.lacus = None
                    console.print(f'[red]WARNING[/red]: Remote lacus is configured but not reachable: {remote_lacus_url}.')

    @property
    def backend_status(self) -> bool:
        socket_path_cache = get_socket_path('cache')
        socket_path_index = get_socket_path('indexing')
        backend_up = True
        if not os.path.exists(socket_path_cache):
            console.print(f'Socket path for the [blue]cache[/blue] redis DB [red]does not exists[/red] ({socket_path_cache}).')
            backend_up = False
        if not os.path.exists(socket_path_index):
            console.print(f'Socket path for the [blue]indexing[/blue] redis DB [red]does not exists[/red] ({socket_path_index}).')
            backend_up = False
        if backend_up:
            try:
                cache_reachable = True if self.redis_cache.ping() else False
                if not cache_reachable:
                    console.print('Unable to ping the redis cache db.')
                    backend_up = False
            except ConnectionError:
                console.print('Unable to connect to the redis cache db.')
                backend_up = False
            try:
                indexing_reachable = True if self.redis_indexing.ping() else False
                if not indexing_reachable:
                    console.print('Unable to ping the redis indexing db.')
                    backend_up = False
            except ConnectionError:
                console.print('Unable to connect to the redis indexing db.')
                backend_up = False

        return backend_up

    @property
    def queues(self) -> list[tuple[str, float]]:
        return self.redis_cache.zrevrangebyscore('queues', 'Inf', '-Inf', withscores=True)

    @property
    def ongoing_captures(self) -> list[tuple[str, float, dict[str, Any]]]:
        captures_uuid: list[tuple[str, float]] = self.redis_cache.zrevrangebyscore('to_capture', 'Inf', '-Inf', withscores=True)
        if not captures_uuid:
            return []
        to_return = []
        for uuid, rank in captures_uuid:
            capture_params = self.redis_cache.hgetall(uuid)
            if 'document' in capture_params:
                capture_params.pop('document')
            if capture_params:
                to_return.append((uuid, rank, capture_params))

        return to_return

    @property
    def tree_cache(self) -> dict[str, str]:
        to_return = {}
        for pid_name, value in self.redis_cache.hgetall('tree_cache').items():
            pid, name = pid_name.split('|', 1)
            try:
                os.kill(int(pid), 0)
            except OSError:
                self.redis_cache.hdel('tree_cache', pid_name)
                continue
            to_return[pid_name] = value
        return to_return

    def lacus_status(self) -> dict[str, Any]:
        if not self.lacus:
            return {}
        to_return = {}
        to_return['is_busy'] = self.lacus.is_busy()
        status = self.lacus.status()
        to_return['max_concurrent_captures'] = status['max_concurrent_captures']
        to_return['ongoing_captures'] = status['ongoing_captures']
        to_return['enqueued_captures'] = status['enqueued_captures']
        return to_return


if __name__ == '__main__':

    m = Monitoring()
    backend_up = m.backend_status
    if not backend_up:
        console.print('[bold red]Backend not up, breaking.[/bold red]')
        sys.exit()

    console.print('Services currently running:')
    running = AbstractManager.is_running()
    for service, number in running:
        s = Padding(f'{service} ({int(number)} service(s))', (0, 2))
        console.print(s)

    console.print('Current cache status:')
    for name, status in m.tree_cache.items():
        s = Padding(f'{name}: {status}', (0, 2))
        console.print(s)

    if m.lacus is not None:
        lacus_status = m.lacus_status()
        console.print('Lacus status:')
        if lacus_status['is_busy']:
            console.print(Padding('[red]WARNING[/red]: Lacus is busy.', (0, 2)))
        console.print(Padding(f'Ongoing captures: {lacus_status["ongoing_captures"]}', (0, 2)))
        console.print(Padding(f'Enqueued captures: {lacus_status["enqueued_captures"]}', (0, 2)))

    console.print('Current queues:')
    for q, priority in m.queues:
        s = Padding(f'{q} Recently enqueued captures: {int(priority)}', (0, 2))
        console.print(s)
    # ------------------
    console.print('Captures details:')
    captures = m.ongoing_captures
    console.print(f'Queue length: [yellow]{len(captures)}[/yellow]')
    for uuid, rank, d in captures:
        a = Padding(f'{uuid} Rank: {int(rank)}', (0, 2))
        console.print(a)
        console.print(d)
