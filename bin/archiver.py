#!/usr/bin/env python3

import csv
import gzip
import logging
import logging.config
import shutil

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

from redis import Redis

from lookyloo.default import AbstractManager, get_config, get_homedir, get_socket_path
from lookyloo.helpers import get_captures_dir

logging.config.dictConfig(get_config('logging'))


class Archiver(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'archiver'
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

        # make sure archived captures dir exists
        self.archived_captures_dir = get_homedir() / 'archived_captures'
        self.archived_captures_dir.mkdir(parents=True, exist_ok=True)

        self._load_indexes()

    def _to_run_forever(self):
        self._archive()
        self._update_all_capture_indexes()
        self._load_indexes()
        self._compress_hars()

    def _update_index(self, root_dir: Path) -> None:
        current_index: Dict[str, str] = {}

        index_file = root_dir / 'index'
        if index_file.exists():
            # Skip index if the directory has been archived.
            existing_captures = index_file.parent.iterdir()
            try:
                with index_file.open('r') as _f:
                    current_index = {uuid: dirname for uuid, dirname in csv.reader(_f) if (index_file.parent / dirname) in existing_captures}
            except Exception as e:
                # the index file is broken, it will be recreated.
                self.logger.warning(f'Index for {root_dir} broken, recreating it: {e}')
                pass
            if not current_index:
                index_file.unlink()

        for uuid_file in root_dir.glob('*/uuid'):
            if uuid_file.parent.name in current_index.values():
                # The path is already in the index file, no need to read the uuid file
                continue
            with uuid_file.open() as _f:
                current_index[_f.read().strip()] = uuid_file.parent.name

        if not current_index:
            # The directory has been archived. It is probably safe to unlink, but
            # if it's not, we will lose a whole buch of captures. Moving instead for safety.
            root_dir.rename(get_homedir() / 'discarded_captures' / root_dir.name)
            return

        with index_file.open('w') as _f:
            index_writer = csv.writer(_f)
            for uuid, dirname in current_index.items():
                index_writer.writerow([uuid, dirname])

    def _update_all_capture_indexes(self):
        '''Run that after the captures are in the proper directories'''
        # Recent captures
        self.logger.info('Update recent indexes')
        directories_to_index = {capture_dir.parent.parent for capture_dir in get_captures_dir().rglob('uuid')}
        for directory_to_index in directories_to_index:
            self.logger.debug(f'Updating index for {directory_to_index}')
            self._update_index(directory_to_index)
        self.logger.info('Recent indexes updated')

        # Archived captures
        self.logger.info('Update archives indexes')
        directories_to_index = {capture_dir.parent.parent for capture_dir in self.archived_captures_dir.rglob('uuid')}
        for directory_to_index in directories_to_index:
            self.logger.debug(f'Updating index for {directory_to_index}')
            self._update_index(directory_to_index)
        self.logger.info('Archived indexes updated')

    def _archive(self):
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval).date()
        cut_time = cut_time.replace(day=1)

        # Format:
        # { 2020: { 12: [(directory, uuid)] } }
        to_archive: Dict[int, Dict[int, List[Path]]] = defaultdict(lambda: defaultdict(list))
        for capture_uuid in get_captures_dir().rglob('uuid'):
            try:
                timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S.%f')
            except ValueError:
                timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S')
            if timestamp.date() >= cut_time:
                continue
            to_archive[timestamp.year][timestamp.month].append(capture_uuid.parent)
            self.logger.info(f'Archiving {capture_uuid.parent}.')

        if not to_archive:
            self.logger.info('Nothing to archive.')
            return

        p = self.redis.pipeline()
        for year, month_captures in to_archive.items():
            for month, captures in month_captures.items():
                dest_dir = self.archived_captures_dir / str(year) / f'{month:02}'
                dest_dir.mkdir(parents=True, exist_ok=True)
                for capture_path in captures:
                    p.delete(str(capture_path))
                    (capture_path / 'tree.pickle').unlink(missing_ok=True)
                    (capture_path / 'tree.pickle.gz').unlink(missing_ok=True)
                    capture_path.rename(dest_dir / capture_path.name)
        p.execute()

        self.logger.info('Archiving done.')

    def _compress_hars(self):
        self.logger.info('Compressing archived captures')
        for index in self.archived_captures_dir.rglob('index'):
            with index.open('r') as _f:
                for uuid, dirname in csv.reader(_f):
                    for har in (index.parent / dirname).rglob('*.har'):
                        if not har.exists():
                            continue
                        with har.open('rb') as f_in:
                            with gzip.open(f'{har}.gz', 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        har.unlink()
        self.logger.info('Archived captures compressed')

    def _load_indexes(self):
        # Initialize archives
        for index in get_captures_dir().rglob('index'):
            with index.open('r') as _f:
                recent_uuids: Mapping = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f) if (index.parent / dirname).exists()}
            if recent_uuids:
                self.redis.hset('lookup_dirs', mapping=recent_uuids)
            else:
                index.unlink()
        self.logger.info('Recent indexes loaded')

        # Initialize archives
        for index in self.archived_captures_dir.rglob('index'):
            with index.open('r') as _f:
                archived_uuids: Mapping = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f) if (index.parent / dirname).exists()}
            if archived_uuids:
                self.redis.hset('lookup_dirs_archived', mapping=archived_uuids)
                self.redis.hdel('lookup_dirs', *archived_uuids.keys())
            else:
                index.unlink()
        self.logger.info('Archived indexes loaded')


def main():
    a = Archiver()
    a.run(sleep_in_sec=3600)


if __name__ == '__main__':
    main()
