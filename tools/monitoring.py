#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

from typing import List, Tuple

from redis import Redis
from redis.exceptions import ConnectionError
from rich.console import Console
from rich.padding import Padding

from lookyloo.helpers import get_socket_path, splash_status
from lookyloo.abstractmanager import AbstractManager

# NOTE: run with watch:
#   watch --color tools/monitoring.py

console = Console(color_system="256")


class Monitoring():

    def __init__(self) -> None:
        self.redis_cache: Redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)
        self.redis_indexing: Redis = Redis(unix_socket_path=get_socket_path('indexing'), decode_responses=True)

    @property
    def backend_status(self):
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
        console.print(f'[green]{message}[/green]')
    else:
        console.print('Splash is [bold red]down[/bold red]: ', message)

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

    console.print('Current queues:')
    for q, priority in m.queues:
        s = Padding(f'{q} Priority: {int(priority)}', (0, 2))
        console.print(s)
    # ------------------
    console.print('Captures details:')
    captures = m.ongoing_captures
    console.print(f'Queue length: [yellow]{len(captures)}[/yellow]')
    for uuid, rank, d in captures:
        a = Padding(f'{uuid} Rank: {int(rank)}', (0, 2))
        console.print(a)
        console.print(d)
