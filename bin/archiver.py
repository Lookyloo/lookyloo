#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections import defaultdict
import csv
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple
from pathlib import Path

from lookyloo.abstractmanager import AbstractManager
from lookyloo.lookyloo import Lookyloo
from lookyloo.helpers import get_config

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class Archiver(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'archiver'
        self._load_indexes()

    def _to_run_forever(self):
        self._archive()

    def _archive(self):
        # Initialize the lookyloo class here, no need to keep it in memory all the time.
        lookyloo = Lookyloo()
        # make sure archived captures dir exists
        archived_captures_dir = lookyloo.capture_dir.parent / 'archived_captures'
        archived_captures_dir.mkdir(parents=True, exist_ok=True)
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval).date()
        cut_time = cut_time.replace(day=1)

        # Format:
        # { 2020: { 12: [(directory, uuid)] } }
        to_archive: Dict[int, Dict[int, List[Tuple[Path, str]]]] = defaultdict(lambda: defaultdict(list))
        for capture_path in lookyloo.capture_dir.glob('*'):
            if not capture_path.is_dir():
                continue
            timestamp = datetime.strptime(capture_path.name, '%Y-%m-%dT%H:%M:%S.%f')
            if timestamp.date() >= cut_time:
                # do not archive.
                continue
            with (capture_path / 'uuid').open() as _f:
                uuid = _f.read().strip()
            to_archive[timestamp.year][timestamp.month].append((capture_path, uuid))
            self.logger.info(f'Archiving {capture_path}.')

        if not to_archive:
            self.logger.info('Nothing to archive.')
            return

        archived_uuids = {}
        for year, month_captures in to_archive.items():
            for month, captures in month_captures.items():
                dest_dir = archived_captures_dir / str(year) / f'{month:02}'
                dest_dir.mkdir(parents=True, exist_ok=True)
                if (dest_dir / 'index').exists():
                    with (dest_dir / 'index').open('r') as _f:
                        current_index = {uuid: dirname for uuid, dirname in csv.reader(_f)}
                else:
                    current_index = {}
                for capture_path, uuid in captures:
                    current_index[uuid] = capture_path.name
                    capture_path.rename(dest_dir / capture_path.name)
                    archived_uuids[uuid] = str(dest_dir / capture_path.name)
                with (dest_dir / 'index').open('w') as _f:
                    index_writer = csv.writer(_f)
                    for uuid, dirname in current_index.items():
                        index_writer.writerow([uuid, dirname])

        if archived_uuids:
            lookyloo.redis.hdel('lookup_dirs', *archived_uuids.keys())
            lookyloo.redis.hset('lookup_dirs_archived', mapping=archived_uuids)
            lookyloo.clear_captures_index_cache(archived_uuids.keys())
        self.logger.info('Archiving done.')

    def _load_indexes(self):
        # Initialize the lookyloo class here, no need to keep it in memory all the time.
        lookyloo = Lookyloo()
        # make sure archived captures dir exists
        archived_captures_dir = lookyloo.capture_dir.parent / 'archived_captures'
        archived_captures_dir.mkdir(parents=True, exist_ok=True)
        for year in archived_captures_dir.iterdir():
            for month in year.iterdir():
                if not (month / 'index').exists():
                    continue
                with (month / 'index').open('r') as _f:
                    archived_uuids = {uuid: str(month / dirname) for uuid, dirname in csv.reader(_f)}
                lookyloo.redis.hset('lookup_dirs_archived', mapping=archived_uuids)
                lookyloo.redis.hdel('lookup_dirs', *archived_uuids.keys())


def main():
    a = Archiver()
    a.run(sleep_in_sec=3600 * 24)


if __name__ == '__main__':
    main()
