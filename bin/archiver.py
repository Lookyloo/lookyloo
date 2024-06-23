#!/usr/bin/env python3

from __future__ import annotations

import csv
import gzip
import logging
import logging.config
import os
import random
import shutil

from datetime import datetime, timedelta
from pathlib import Path

from redis import Redis
import s3fs  # type: ignore[import-untyped]

from lookyloo.default import AbstractManager, get_config, get_homedir, get_socket_path, try_make_file
from lookyloo.helpers import get_captures_dir, is_locked, make_ts_from_dirname, make_dirs_list

logging.config.dictConfig(get_config('logging'))


class Archiver(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
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
            self.s3fs_client = s3fs.S3FileSystem(key=s3fs_config['config']['key'],
                                                 secret=s3fs_config['config']['secret'],
                                                 endpoint_url=s3fs_config['config']['endpoint_url'],
                                                 config_kwargs={'connect_timeout': 10,
                                                                'read_timeout': 900})
            self.s3fs_bucket = s3fs_config['config']['bucket_name']
            self.s3fs_client.clear_multipart_uploads(self.s3fs_bucket)

    def _to_run_forever(self) -> None:
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
            if not archiving_done:
                self._update_all_capture_indexes(recent_only=True)
        if not self.shutdown_requested():
            # This call takes a very long time on MinIO
            self._update_all_capture_indexes()

    def _update_index(self, root_dir: Path, *, s3fs_parent_dir: str | None=None) -> Path | None:
        # returns a path to the index for the given directory
        logmsg = f'Updating index for {root_dir}'
        if s3fs_parent_dir:
            logmsg = f'{logmsg} (s3fs)'
        self.logger.info(logmsg)

        current_index: dict[str, str] = {}
        index_file = root_dir / 'index'
        if index_file.exists():
            try:
                current_index = self.__load_index(index_file, ignore_sub=True)
            except Exception as e:
                # the index file is broken, it will be recreated.
                self.logger.warning(f'Index for {root_dir} broken, recreating it: {e}')
            if not current_index:
                # The file is either empty or only contains subs
                # NOTE: should we remove if it has subs?
                index_file.unlink()

        sub_indexes: list[Path] = []
        current_index_dirs: set[str] = set(current_index.values())
        new_captures: set[Path] = set()
        # Directories that are actually in the listing.
        current_dirs: set[str] = set()

        if s3fs_parent_dir:
            s3fs_dir = '/'.join([s3fs_parent_dir, root_dir.name])
            # the call below will spit out a mix of directories:
            # * <datetime>
            # * <day> (which contains a <datetime> directory)
            for entry in self.s3fs_client.ls(s3fs_dir, detail=False, refresh=False):
                if entry.endswith('/'):
                    # root directory
                    continue
                if not self.s3fs_client.isdir(entry):
                    # index
                    continue
                dir_on_disk = root_dir / entry.rsplit('/', 1)[-1]
                if dir_on_disk.name.isdigit():
                    if sub_index := self._update_index(dir_on_disk, s3fs_parent_dir=s3fs_dir):
                        # got a day directory that contains captures
                        sub_indexes.append(sub_index)
                else:
                    # got a capture
                    if len(self.s3fs_client.ls(entry, detail=False)) == 1:
                        # empty capture directory
                        self.s3fs_client.rm(entry)
                        continue
                    if str(dir_on_disk) not in current_index_dirs:
                        new_captures.add(dir_on_disk)
                current_dirs.add(dir_on_disk.name)
                current_dirs.add(str(dir_on_disk))

        else:
            with os.scandir(root_dir) as it:
                for entry in it:
                    # can be index, sub directory (digit), or isoformat
                    if not entry.is_dir():
                        # index
                        continue
                    dir_on_disk = Path(entry)
                    if dir_on_disk.name.isdigit():
                        if sub_index := self._update_index(dir_on_disk):
                            # got a day directory that contains captures
                            sub_indexes.append(sub_index)
                    else:
                        # isoformat
                        if str(dir_on_disk) not in current_index_dirs:
                            new_captures.add(dir_on_disk)
                    current_dirs.add(dir_on_disk.name)
                    current_dirs.add(str(dir_on_disk))

        # Check if all the directories in current_dirs (that we got by listing the directory)
        # are the same as the one in the index. If they're not, we pop the UUID before writing the index
        if non_existing_dirs := current_index_dirs - current_dirs:
            self.logger.info(f'Got {len(non_existing_dirs)} non existing dirs in {root_dir}, removing them from the index.')
            current_index = {uuid: Path(path).name for uuid, path in current_index.items() if path not in non_existing_dirs}

        if not current_index and not new_captures and not sub_indexes:
            # No captures at all in the directory and subdirectories, quitting
            logmsg = f'No captures in {root_dir}'
            if s3fs_parent_dir:
                logmsg = f'{logmsg} (s3fs directory)'
            self.logger.info(logmsg)
            index_file.unlink(missing_ok=True)
            root_dir.rmdir()
            return None

        if new_captures:
            self.logger.info(f'{len(new_captures)} new captures in {root_dir}.')

        for capture_dir in new_captures:
            # capture_dir_name is *only* the isoformat of the capture.
            # This directory will either be directly in the month directory (old format)
            # or in the day directory (new format)
            try:
                if not next(capture_dir.iterdir(), None):
                    self.logger.warning(f'{capture_dir} is empty, removing.')
                    capture_dir.rmdir()
                    continue
            except FileNotFoundError:
                self.logger.warning(f'{capture_dir} does not exists.')
                continue

            try:
                uuid_file = capture_dir / 'uuid'
                if not uuid_file.exists():
                    self.logger.warning(f'No UUID file in {capture_dir}.')
                    shutil.move(str(capture_dir), str(get_homedir() / 'discarded_captures'))
                    continue

                with uuid_file.open() as _f:
                    uuid = _f.read().strip()
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
            current_index[uuid] = capture_dir.name

        if not current_index and not sub_indexes:
            # The directory has been archived. It is probably safe to unlink, but
            # if it's not, we will lose a whole buch of captures. Moving instead for safety.
            shutil.move(str(root_dir), str(get_homedir() / 'discarded_captures' / root_dir.parent / root_dir.name))
            self.logger.warning(f'Nothing to index in {root_dir}')
            return None

        with index_file.open('w') as _f:
            index_writer = csv.writer(_f)
            for uuid, dirname in current_index.items():
                index_writer.writerow([uuid, dirname])
            for sub_path in sub_indexes:
                # Only keep the dir name
                index_writer.writerow(['sub_index', sub_path.parent.name])

        return index_file

    def _update_all_capture_indexes(self, *, recent_only: bool=False) -> None:
        '''Run that after the captures are in the proper directories'''
        # Recent captures
        self.logger.info('Update recent indexes')
        # NOTE: the call below will check the existence of every path ending with `uuid`,
        #       it is extremely ineficient as we have many hundred of thusands of them
        #       and we only care about the root directory (ex: 2023/06)
        # directories_to_index = {capture_dir.parent.parent
        #                        for capture_dir in get_captures_dir().glob('*/*/*/uuid')}
        for directory_to_index in make_dirs_list(get_captures_dir()):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            self._update_index(directory_to_index)
        self.logger.info('Recent indexes updated')
        if recent_only:
            self.logger.info('Only updating recent indexes.')
            return

        # Archived captures
        self.logger.info('Update archives indexes')
        for directory_to_index in make_dirs_list(self.archived_captures_dir):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            year = directory_to_index.parent.name
            if self.archive_on_s3fs:
                # Updating the indexes can take a while, just run this call once in N calls
                if random.randrange(20) == 0:
                    self._update_index(directory_to_index,
                                       s3fs_parent_dir='/'.join([self.s3fs_bucket, year]))
            else:
                self._update_index(directory_to_index)
        self.logger.info('Archived indexes updated')

    def __archive_single_capture(self, capture_path: Path) -> Path:
        capture_timestamp = make_ts_from_dirname(capture_path.name)
        dest_dir = self.archived_captures_dir / str(capture_timestamp.year) / f'{capture_timestamp.month:02}' / f'{capture_timestamp.day:02}'
        dest_dir.mkdir(parents=True, exist_ok=True)
        # If the HAR isn't archived yet, archive it before copy
        for har in capture_path.glob('*.har'):
            with har.open('rb') as f_in:
                with gzip.open(f'{har}.gz', 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            har.unlink()

        # read uuid before copying over to (maybe) S3
        with (capture_path / 'uuid').open() as _uuid:
            uuid = _uuid.read().strip()

        (capture_path / 'tree.pickle').unlink(missing_ok=True)
        (capture_path / 'tree.pickle.gz').unlink(missing_ok=True)
        shutil.move(str(capture_path), str(dest_dir))
        # Update index in parent
        with (dest_dir / 'index').open('a') as _index:
            index_writer = csv.writer(_index)
            index_writer.writerow([uuid, capture_path.name])
        # Update redis cache all at once.
        p = self.redis.pipeline()
        p.delete(str(capture_path))
        p.hset('lookup_dirs_archived', mapping={uuid: str(dest_dir / capture_path.name)})
        p.hdel('lookup_dirs', uuid)
        p.execute()

        return dest_dir / capture_path.name

    def _archive(self) -> bool:
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval)
        self.logger.info(f'Archiving all captures older than {cut_time.isoformat()}.')
        archiving_done = True

        # Let's use the indexes instead of listing directories to find what we want to archive.
        capture_breakpoint = 300
        for u, p in self.redis.hscan_iter('lookup_dirs'):
            uuid = u.decode()
            path = p.decode()
            if capture_breakpoint <= 0:
                # Break and restart later
                self.logger.info('Archived many captures will keep going later.')
                archiving_done = False
                break
            elif capture_breakpoint % 10:
                # Just check if we requested a shutdown.
                if self.shutdown_requested():
                    self.logger.warning('Shutdown requested, breaking.')
                    break

            capture_time_isoformat = os.path.basename(path)
            if not capture_time_isoformat:
                continue
            try:
                capture_time = make_ts_from_dirname(capture_time_isoformat)
            except ValueError:
                self.logger.warning(f'Invalid capture time for {uuid}: {capture_time_isoformat}')
                self.redis.hdel('lookup_dirs', uuid)
                continue
            if capture_time >= cut_time:
                continue
            # archive the capture.
            capture_path = Path(path)
            if not capture_path.exists():
                self.redis.hdel('lookup_dirs', uuid)
                if not self.redis.hexists('lookup_dirs_archived', uuid):
                    self.logger.warning(f'Missing capture directory for {uuid}, unable to archive {capture_path}')
                continue
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

            try:
                new_capture_path = self.__archive_single_capture(capture_path)
                capture_breakpoint -= 1
            except OSError:
                self.logger.exception(f'Unable to archive capture {capture_path}')
                (capture_path / 'lock').unlink(missing_ok=True)
            except Exception:
                self.logger.exception(f'Critical exception while archiving {capture_path}')
                (capture_path / 'lock').unlink(missing_ok=True)
            else:
                (new_capture_path / 'lock').unlink(missing_ok=True)

        if archiving_done:
            self.logger.info('Archiving done.')
        return archiving_done

    def __load_index(self, index_path: Path, ignore_sub: bool=False) -> dict[str, str]:
        '''Loads the given index file and all the subsequent ones if they exist'''
        # NOTE: this method is used on recent and archived captures, it must never trigger a dir listing
        indexed_captures = {}
        with index_path.open() as _i:
            for key, path_name in csv.reader(_i):
                if key == 'sub_index' and not ignore_sub:
                    sub_index_file = index_path.parent / path_name / 'index'
                    if sub_index_file.exists():
                        indexed_captures.update(self.__load_index(sub_index_file))
                    else:
                        self.logger.warning(f'Missing sub index file: {sub_index_file}')
                else:
                    # NOTE: we were initially checking if that path exists,
                    #       but that's something we can do when we update the indexes instead.
                    #       And a missing capture directory is already handled at rendering
                    indexed_captures[key] = str(index_path.parent / path_name)
        return indexed_captures

    def _load_indexes(self) -> None:
        # capture_dir / Year / Month / index <- should always exists. If not, created by _update_index
        # Initialize recent index
        for index in sorted(get_captures_dir().glob('*/*/index'), reverse=True):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break

            self.logger.debug(f'Loading {index}')
            if recent_uuids := self.__load_index(index):
                self.logger.debug(f'{len(recent_uuids)} captures in directory {index.parent}.')
                self.redis.hset('lookup_dirs', mapping=recent_uuids)  # type: ignore[arg-type]
            else:
                index.unlink()
        total_recent_captures = self.redis.hlen('lookup_dirs')
        self.logger.info(f'Recent indexes loaded: {total_recent_captures} entries.')

        # Initialize archives index
        for index in sorted(self.archived_captures_dir.glob('*/*/index'), reverse=True):
            if self.shutdown_requested():
                self.logger.warning('Shutdown requested, breaking.')
                break
            self.logger.debug(f'Loading {index}')
            if archived_uuids := self.__load_index(index):
                self.logger.debug(f'{len(archived_uuids)} captures in directory {index.parent}.')
                self.redis.hset('lookup_dirs_archived', mapping=archived_uuids)  # type: ignore[arg-type]
            else:
                index.unlink()
        total_archived_captures = self.redis.hlen('lookup_dirs_archived')
        self.logger.info(f'Archived indexes loaded: {total_archived_captures} entries.')


def main() -> None:
    a = Archiver()
    a.run(sleep_in_sec=3600)


if __name__ == '__main__':
    main()
