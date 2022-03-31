#!/usr/bin/env python3

import csv
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

from redis import Redis

from lookyloo.default import AbstractManager, get_config, get_homedir, get_socket_path
from lookyloo.helpers import get_captures_dir

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class Archiver(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'archiver'
        self.redis = Redis(unix_socket_path=get_socket_path('cache'))

        # make sure archived captures dir exists
        self.archived_captures_dir = get_homedir() / 'archived_captures'
        self.archived_captures_dir.mkdir(parents=True, exist_ok=True)

        self._load_indexes()

    def _to_run_forever(self):
        self._archive()
        self._update_all_capture_indexes()
        self._load_indexes()

    def _update_index(self, root_dir: Path) -> None:
        current_index: Dict[str, str] = {}

        index_file = root_dir / 'index'
        if index_file.exists():
            # Skip index if the directory has been archived.
            existing_captures = index_file.parent.iterdir()
            try:
                with index_file.open('r') as _f:
                    current_index = {uuid: dirname for uuid, dirname in csv.reader(_f) if (index_file.parent / dirname) in existing_captures}
            except Exception:
                # the index file is broken, it will be recreated.
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
        directories_to_index = {capture_dir.parent.parent for capture_dir in get_captures_dir().glob('**/uuid')}
        for directory_to_index in directories_to_index:
            self._update_index(directory_to_index)

        # Archived captures
        directories_to_index = {capture_dir.parent.parent for capture_dir in self.archived_captures_dir.glob('**/uuid')}
        for directory_to_index in directories_to_index:
            self._update_index(directory_to_index)

    def _archive(self):
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval).date()
        cut_time = cut_time.replace(day=1)

        # Format:
        # { 2020: { 12: [(directory, uuid)] } }
        to_archive: Dict[int, Dict[int, List[Path]]] = defaultdict(lambda: defaultdict(list))
        for capture_uuid in get_captures_dir().glob('**/uuid'):
            timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S.%f')
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
                    capture_path.rename(dest_dir / capture_path.name)
        p.execute()

        # Clear empty

        self.logger.info('Archiving done.')

    def _load_indexes(self):
        # Initialize archives
        for index in get_captures_dir().glob('**/index'):
            with index.open('r') as _f:
                recent_uuids: Dict[str, str] = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f) if (index.parent / dirname).exists()}
            if recent_uuids:
                self.redis.hmset('lookup_dirs', recent_uuids)  # type: ignore
            else:
                index.unlink()

        # Initialize archives
        for index in self.archived_captures_dir.glob('**/index'):
            with index.open('r') as _f:
                archived_uuids: Dict[str, str] = {uuid: str(index.parent / dirname) for uuid, dirname in csv.reader(_f) if (index.parent / dirname).exists()}
            if archived_uuids:
                self.redis.hmset('lookup_dirs_archived', archived_uuids)  # type: ignore
            else:
                index.unlink()


def main():
    a = Archiver()
    a.run(sleep_in_sec=3600)


if __name__ == '__main__':
    main()
