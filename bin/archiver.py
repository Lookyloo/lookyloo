#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections import defaultdict
import csv
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple
from pathlib import Path

from redis import Redis

from lookyloo.abstractmanager import AbstractManager
from lookyloo.helpers import get_config, get_homedir, get_socket_path, get_captures_dir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO, datefmt='%I:%M:%S')


class Archiver(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'archiver'
        self.redis = Redis(unix_socket_path=get_socket_path('cache'))

        # make sure archived captures dir exists
        self.archived_captures_dir = get_homedir() / 'archived_captures'
        self.archived_captures_dir.mkdir(parents=True, exist_ok=True)

        self._load_archives()

    def _to_run_forever(self):
        self._archive()

    def _archive(self):
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval).date()
        cut_time = cut_time.replace(day=1)

        # Format:
        # { 2020: { 12: [(directory, uuid)] } }
        to_archive: Dict[int, Dict[int, List[Tuple[Path, str]]]] = defaultdict(lambda: defaultdict(list))
        for capture_uuid in get_captures_dir().glob('**/uuid'):
            timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S.%f')
            if timestamp.date() >= cut_time:
                # do not archive.
                continue
            with capture_uuid.open() as _f:
                uuid = _f.read().strip()
            to_archive[timestamp.year][timestamp.month].append((capture_uuid.parent, uuid))
            self.logger.info(f'Archiving {capture_uuid.parent}.')

        if not to_archive:
            self.logger.info('Nothing to archive.')
            return

        archived_uuids = {}
        for year, month_captures in to_archive.items():
            for month, captures in month_captures.items():
                dest_dir = self.archived_captures_dir / str(year) / f'{month:02}'
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
            p = self.redis.pipeline()
            for dir_key in self.redis.hmget('lookup_dirs', *archived_uuids.keys()):
                # Clear cache
                if dir_key:
                    p.delete(dir_key)
            p.hdel('lookup_dirs', *archived_uuids.keys())
            p.hmset('lookup_dirs_archived', archived_uuids)  # type: ignore
            p.execute()
        self.logger.info('Archiving done.')

    def _load_archives(self):
        # Initialize archives
        self.redis.delete('lookup_dirs_archived')
        for index in self.archived_captures_dir.glob('**/index'):
            with index.open('r') as _f:
                archived_uuids: Dict[str, str] = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f)}
            self.redis.hmset('lookup_dirs_archived', archived_uuids)  # type: ignore


def main():
    a = Archiver()
    a.run(sleep_in_sec=3600 * 24)


if __name__ == '__main__':
    main()
