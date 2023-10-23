#!/usr/bin/env python3

import csv
import gzip
import logging
import logging.config
import os
import shutil

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Dict, List, Optional

from redis import Redis
import s3fs  # type: ignore

from lookyloo.default import AbstractManager, get_config, get_homedir, get_socket_path, try_make_file
from lookyloo.helpers import get_captures_dir, is_locked

logging.config.dictConfig(get_config('logging'))


class Archiver(AbstractManager):

    def __init__(self, loglevel: Optional[int]=None):
        super().__init__(loglevel)
        self.script_name = 'archiver'
        self.redis = Redis(unix_socket_path=get_socket_path('cache'))

        # make sure archived captures dir exists
        self.archived_captures_dir = get_homedir() / 'archived_captures'
        self.archived_captures_dir.mkdir(parents=True, exist_ok=True)

        self._load_indexes()

        # NOTE 2023-10-03: if we store the archived captures in s3fs (as it is the case in the CIRCL demo instance),
        # listing the directories directly with s3fs-fuse causes I/O errors and is making the interface unusable.
        # It is only a problem on directory listing and not when accessing a capture, so we only need to change the way
        # we generate the index files.
        # Other issue: the python module s3fs requires urllib < 2.0 (https://github.com/boto/botocore/issues/2926) so
        # we cannot run the script creating the indexes in the same virtual environment as the rest of the project.
        # The variable below will only be used to make sure we don't try to trigger a directory listing on a s3fs-fuse mount
        # and we're going to create the index files from another script, in tools/create_archive_indexes.
        self.archive_on_s3fs = False
        s3fs_config = get_config('generic', 's3fs')
        if s3fs_config.get('archive_on_s3fs'):
            self.archive_on_s3fs = True
            self.s3fs_client = s3fs.S3FileSystem(key=s3fs_config['key'],
                                                 secret=s3fs_config['secret'],
                                                 endpoint_url=s3fs_config['endpoint_url'],
                                                 config_kwargs={'connect_timeout': 10,
                                                                'read_timeout': 900})
            self.s3fs_bucket = s3fs_config['bucket_name']
            self.s3fs_client.clear_multipart_uploads(self.s3fs_bucket)

    def _to_run_forever(self):
        archiving_done = False
        # NOTE: When we archive a big directory, moving *a lot* of files, expecially to MinIO
        # can take a very long time. In order to avoid being stuck on the archiving, we break that in chunks
        # but we also want to keep archiving without waiting 1h between each run.
        while not archiving_done:
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            archiving_done = self._archive()
            self._load_indexes()
            # The HARs are supposedly all compressed so this call shouldn't be required
            # unless you're processing old captures for the first time.
            # self._compress_hars()
        if not self.shutdown_requested():
            # This call takes a very long time on MinIO
            self._update_all_capture_indexes()

    def _update_index(self, root_dir: Path, *, s3fs: bool=False) -> None:
        current_index: Dict[str, str] = {}
        if s3fs:
            self.s3fs_client.invalidate_cache(str(root_dir))
            all_s3fs_captures = self.s3fs_client.ls(str(root_dir), detail=False, refresh=True)
            if not all_s3fs_captures:
                self.s3fs_client.rmdir(str(root_dir))
                return
        else:
            if not any(os.scandir(root_dir)):
                # the directory is empty, we can safely remove it
                root_dir.rmdir()
                return

        self.logger.debug(f'Updating index for {root_dir}')
        index_file = root_dir / 'index'
        if index_file.exists():
            # Skip index if the directory has been archived.
            try:
                with index_file.open('r') as _f:
                    current_index = {uuid: dirname for uuid, dirname in csv.reader(_f)
                                     if uuid and dirname}
            except Exception as e:
                # the index file is broken, it will be recreated.
                self.logger.warning(f'Index for {root_dir} broken, recreating it: {e}')
                pass
            if not current_index:
                index_file.unlink()

        curent_index_dirs = set(current_index.values())

        if s3fs:
            new_captures = {existing_capture.rsplit('/', 1)[-1] for existing_capture in all_s3fs_captures
                            if existing_capture.rsplit('/', 1)[-1]
                            and (existing_capture.rsplit('/', 1)[-1] not in curent_index_dirs)
                            and self.s3fs_client.is_dir(str(existing_capture))}
        else:
            with os.scandir(root_dir) as it:
                new_captures = {existing_capture.name for existing_capture in it
                                if (existing_capture.name not in curent_index_dirs)
                                and existing_capture.is_dir()}

        if not new_captures:
            # No new captures, quitting
            self.logger.debug(f'No new captures in {root_dir}.')
            return

        self.logger.info(f'{len(new_captures)} new captures in {root_dir}.')

        for capture_dir_name in new_captures:
            capture_dir = root_dir / capture_dir_name
            if not next(capture_dir.iterdir(), None):
                self.logger.warning(f'{capture_dir} is empty, removing.')
                capture_dir.rmdir()
                continue
            uuid_file = capture_dir / 'uuid'
            if not uuid_file.exists():
                self.logger.warning(f'No UUID file in {capture_dir}.')
                shutil.move(str(capture_dir), str(get_homedir() / 'discarded_captures'))
                continue
            with uuid_file.open() as _f:
                uuid = _f.read().strip()

            try:
                if not uuid:
                    self.logger.warning(f'{uuid_file} is empty')
                    shutil.move(str(capture_dir), str(get_homedir() / 'discarded_captures'))
                    continue
                if uuid in current_index:
                    self.logger.warning(f'Duplicate UUID ({uuid}) in {current_index[uuid]} and {uuid_file.parent.name}')
                    shutil.move(str(capture_dir), str(get_homedir() / 'discarded_captures'))
                    continue
            except OSError as e:
                self.logger.warning(f'Error when discarding capture {capture_dir}: {e}')
                continue

            current_index[uuid] = uuid_file.parent.name

        if not current_index:
            # The directory has been archived. It is probably safe to unlink, but
            # if it's not, we will lose a whole buch of captures. Moving instead for safety.
            shutil.move(str(root_dir), str(get_homedir() / 'discarded_captures' / root_dir.parent / root_dir.name))
            return

        with index_file.open('w') as _f:
            index_writer = csv.writer(_f)
            for uuid, dirname in current_index.items():
                index_writer.writerow([uuid, dirname])

    def _make_dirs_list(self, root_dir: Path) -> List[Path]:
        directories = []
        year_now = date.today().year
        while True:
            year_dir = root_dir / str(year_now)
            if not year_dir.exists():
                # if we do not have a directory with this year, quit the loop
                break
            for month in range(12, 0, -1):
                month_dir = year_dir / f'{month:02}'
                if month_dir.exists():
                    directories.append(month_dir)
            year_now -= 1
        return directories

    def _update_all_capture_indexes(self):
        '''Run that after the captures are in the proper directories'''
        # Recent captures
        self.logger.info('Update recent indexes')
        # NOTE: the call below will check the existence of every path ending with `uuid`,
        #       it is extremely ineficient as we have many hundred of thusands of them
        #       and we only care about the root directory (ex: 2023/06)
        # directories_to_index = {capture_dir.parent.parent
        #                        for capture_dir in get_captures_dir().glob('*/*/*/uuid')}
        for directory_to_index in self._make_dirs_list(get_captures_dir()):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            self._update_index(directory_to_index)
        self.logger.info('Recent indexes updated')
        # Archived captures
        self.logger.info('Update archives indexes')
        for directory_to_index in self._make_dirs_list(self.archived_captures_dir):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            self._update_index(directory_to_index, s3fs=self.archive_on_s3fs)
        self.logger.info('Archived indexes updated')

    def _archive(self):
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval).date()
        cut_time = cut_time.replace(day=1)
        self.logger.info(f'Archiving all captures older than {cut_time.isoformat()}.')
        archiving_done = True

        # Format:
        # { 2020: { 12: [(directory, uuid)] } }
        to_archive: Dict[int, Dict[int, List[Path]]] = defaultdict(lambda: defaultdict(list))
        # In order to avoid scanning the complete directory on each run, we check if year and month are
        # older than the cut time.
        for index in get_captures_dir().glob('*/*/index'):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            month = int(index.parent.name)
            year = int(index.parent.parent.name)
            if date(year, month, 1) >= cut_time:
                continue

            for capture_uuid in index.parent.glob('*/uuid'):
                try:
                    timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S.%f')
                except ValueError:
                    timestamp = datetime.strptime(capture_uuid.parent.name, '%Y-%m-%dT%H:%M:%S')
                if timestamp.date() >= cut_time:
                    continue
                to_archive[timestamp.year][timestamp.month].append(capture_uuid.parent)
                self.logger.debug(f'Archiving {capture_uuid.parent}.')

        if not to_archive:
            self.logger.info('Nothing to archive.')
            return archiving_done

        for year, month_captures in to_archive.items():
            for month, captures in month_captures.items():
                dest_dir = self.archived_captures_dir / str(year) / f'{month:02}'
                dest_dir.mkdir(parents=True, exist_ok=True)
                capture_breakpoint = 300
                self.logger.info(f'{len(captures)} captures to archive in {year}-{month}.')
                for capture_path in captures:
                    if capture_breakpoint <= 0:
                        # Break and restart later
                        self.logger.info(f'Archived many captures in {year}-{month}, will keep going later.')
                        archiving_done = False
                        break
                    elif capture_breakpoint % 10:
                        # Just check if we requested a shutdown.
                        if self.shutdown_requested():
                            self.logger.warning('Shutdown requested, breaking.')
                            break

                    lock_file = capture_path / 'lock'
                    if try_make_file(lock_file):
                        # Lock created, we can proceede
                        with lock_file.open('w') as f:
                            f.write(f"{datetime.now().isoformat()};{os.getpid()}")
                    else:
                        # The directory is locked because a pickle is being created, try again later
                        if is_locked(capture_path):
                            # call this method to remove dead locks
                            continue

                    capture_breakpoint -= 1
                    # If the HAR isn't archived yet, archive it before copy
                    for har in capture_path.glob('*.har'):
                        with har.open('rb') as f_in:
                            with gzip.open(f'{har}.gz', 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        har.unlink()

                    try:
                        (capture_path / 'tree.pickle').unlink(missing_ok=True)
                        (capture_path / 'tree.pickle.gz').unlink(missing_ok=True)
                        shutil.move(str(capture_path), str(dest_dir))
                        self.redis.delete(str(capture_path))
                    except OSError as e:
                        self.logger.warning(f'Unable to archive capture: {e}')
                    finally:
                        (dest_dir / capture_path.name / 'lock').unlink(missing_ok=True)
                # we archived some captures, update relevant index
                self._update_index(dest_dir)
                if not archiving_done:
                    break
            else:
                break
        if archiving_done:
            self.logger.info('Archiving done.')
        return archiving_done

    def _compress_hars(self):
        """This method is very slow (it checks every single capture for non-compressed HARs)
        The new approach is to compress the har of every capture by default so this shouldn't be
        needed anymore. Keeping it here just for reference, or to process old archives that contain
        non-gziped HARs.
        """
        self.logger.info('Compressing archived captures')
        for index in self.archived_captures_dir.glob('*/*/index'):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            with index.open('r') as _f:
                for uuid, dirname in csv.reader(_f):
                    for har in (index.parent / dirname).glob('*.har'):
                        with har.open('rb') as f_in:
                            with gzip.open(f'{har}.gz', 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        har.unlink()
        self.logger.info('Archived captures compressed')

    def _load_indexes(self):
        # Initialize archives
        for index in get_captures_dir().glob('*/*/index'):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break

            self.logger.info(f'Loading {index}')
            with index.open('r') as _f:
                recent_uuids: Mapping = {uuid: str(index.parent / dirname)
                                         for uuid, dirname in csv.reader(_f)
                                         if (index.parent / dirname).exists()}
            if recent_uuids:
                self.logger.info(f'{len(recent_uuids)} captures in directory.')
                self.redis.hset('lookup_dirs', mapping=recent_uuids)
            else:
                index.unlink()
        self.logger.info('Recent indexes loaded')

        already_archived_uuids = {k.decode() for k in self.redis.hkeys('lookup_dirs_archived')}
        self.logger.info(f'Already have {len(already_archived_uuids)} UUIDs archived')
        # Initialize archives
        for index in sorted(self.archived_captures_dir.glob('*/*/index'), reverse=True):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            self.logger.debug(f'Loading {index}')
            with index.open('r') as _f:
                archived_uuids: Mapping = {uuid: index.parent / dirname
                                           for uuid, dirname in csv.reader(_f)}
            if archived_uuids:
                self.logger.debug(f'{len(archived_uuids)} captures in directory.')
                new_uuids = set(archived_uuids.keys()) - already_archived_uuids
                if not new_uuids:
                    self.logger.debug('No new archived UUID to check.')
                    continue

                self.logger.info(f'Loading {index}, {len(archived_uuids)} captures in directory, {len(new_uuids)} archived UUID to check.')
                # NOTE: Only check if the directory exists if the UUID isn't in the cache.
                self.redis.hset('lookup_dirs_archived',
                                mapping={uuid: str(dirname)
                                         for uuid, dirname in archived_uuids.items()
                                         if uuid in new_uuids and dirname.exists()})
                self.redis.hdel('lookup_dirs', *archived_uuids.keys())
            else:
                index.unlink()
        self.logger.info('Archived indexes loaded')


def main():
    a = Archiver()
    a.run(sleep_in_sec=3600)


if __name__ == '__main__':
    main()
