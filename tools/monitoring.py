#!/usr/bin/env python3

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.padding import Padding

from lookyloo import Lookyloo
from lookyloo.monitoring import Monitoring

# NOTE: run with watch:
#   watch --color tools/monitoring.py

console = Console(color_system="256")

if __name__ == '__main__':

    logging.disable(logging.CRITICAL)
    try:
        lookyloo = Lookyloo()
    except Exception as e:
        console.print(e)
        sys.exit()

    m = Monitoring(lookyloo)
    for l_name, info in m.lacuses_status.items():
        status, url = info
        if not status:
            console.print(f'[red]WARNING[/red]: Remote lacus is configured but not reachable: {url}')

    backend_up, details = m.backend_status
    if not backend_up:
        console.print('[bold red]Backend not up, breaking.[/bold red]')
        for d in details:
            console.print(d)
        sys.exit()

    console.print('Services currently running:')
    for service, number, pids, dead_pids in m.services:
        to_print = f'{service} ({int(number)} service(s)) - PIDs: {", ".join(pids)}'
        if dead_pids:
            to_print += ' - Dead PIDs: {", ".join(dead_pids)}'
        s = Padding(to_print, (0, 2))
        console.print(s)

    console.print('Current cache status:')
    for name, _status in m.tree_cache.items():
        s = Padding(f'{name}: {_status}', (0, 2))
        console.print(s)

    console.print('Lacus status:')
    for name, _details in m.lacuses_status_details.items():
        if _details['is_busy']:
            console.print(Padding(f'[red]WARNING[/red]: Lacus {name} is busy.', (0, 2)))
        console.print(Padding(f'[{name}] Ongoing captures: {_details["ongoing_captures"]}', (0, 2)))
        console.print(Padding(f'[{name}] Enqueued captures: {_details["enqueued_captures"]}', (0, 2)))

    console.print('Current queues:')
    for q, priority in m.queues:
        s = Padding(f'{q} Recently enqueued captures: {int(priority)}', (0, 2))
        console.print(s)
    # ------------------
    console.print('Captures details:')
    captures = m.ongoing_captures
    console.print(f'Queue length: [yellow]{len(captures)}[/yellow]')
    for uuid, rank, _d in captures:
        a = Padding(f'{uuid} Rank: {int(rank)}', (0, 2))
        console.print(a)
        console.print(_d)
