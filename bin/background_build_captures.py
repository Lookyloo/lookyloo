#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config
import os
import shutil

from datetime import datetime, timedelta
from pathlib import Path

from redis import Redis

from lookyloo import Lookyloo
from lookyloo_models import AutoReportSettings, MonitorCaptureSettings
from lookyloo.default import AbstractManager, get_config, get_socket_path, try_make_file, LookylooException
from lookyloo.exceptions import UUIDMissingInCache, NoValidHarFile, TreeNeedsRebuild, DuplicateUUID, MissingCaptureDirectory, CaptureLocked, TreeBuildFailed
from lookyloo.helpers import (is_locked, get_sorted_captures_from_disk, make_dirs_list,
                              get_captures_dir, get_archived_captures_dir)


logging.config.dictConfig(get_config('logging'))


class BackgroundBuildCaptures(AbstractManager):

    def __init__(self, recent_only: bool=True, loglevel: int | None=None):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo(cache_max_size=1)
        if recent_only:
            self.script_name = 'background_build_captures'
            self.captures_dir = get_captures_dir()
            self.build_recent = True
            self.lookup_dirs = 'lookup_dirs'
        else:
            # we're building trees for archived captures.
            # if they are on s3, disable, it is way too slow
            if s3fs_config := get_config('generic', 's3fs'):
                if s3fs_config.get('archive_on_s3fs'):
                    raise LookylooException('s3fs is too slow to build archives on')
            self.script_name = 'background_build_captures_archives'
            self.captures_dir = get_archived_captures_dir()
            self.build_recent = False
            self.lookup_dirs = 'lookup_dirs_archived'
        # make sure discarded captures dir exists
        self.discarded_captures_dir = self.captures_dir.parent / 'discarded_captures'
        self.discarded_captures_dir.mkdir(parents=True, exist_ok=True)

        # Redis connector so we don't use the one from Lookyloo
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def __auto_report(self, path: Path) -> None:
        with (path / 'uuid').open() as f:
            capture_uuid = f.read()
        self.logger.info(f'Triggering autoreport for {capture_uuid}...')
        settings: None | AutoReportSettings = None
        with (path / 'auto_report').open('rb') as f:
            if ar := f.read():
                # could be an empty file, which means no settings, just notify
                settings = AutoReportSettings.model_validate_json(ar)
        try:
            self.lookyloo.send_mail(capture_uuid, as_admin=True,
                                    email=settings.email if settings else '',
                                    comment=settings.comment if settings else '')
            (path / 'auto_report').unlink()
        except Exception as e:
            self.logger.warning(f'Unable to send auto report for {capture_uuid}: {e}')
        else:
            self.logger.info(f'Auto report for {capture_uuid} sent.')

    def __auto_monitor(self, path: Path) -> None:
        with (path / 'uuid').open() as f:
            capture_uuid = f.read()
        if not self.lookyloo.monitoring:
            self.logger.warning(f'Unable to monitor {capture_uuid}, not enabled ont he instance.')
            return

        self.logger.info(f'Starting monitoring for {capture_uuid}...')
        monitor_settings: MonitorCaptureSettings | None = None
        try:
            with (path / 'monitor_capture').open('rb') as f:
                if m := f.read():
                    monitor_settings = MonitorCaptureSettings.model_validate_json(m)
        except FileNotFoundError:
            # processed by another script.
            return
        (path / 'monitor_capture').unlink()
        if not monitor_settings:
            self.logger.warning(f'Unable to monitor {capture_uuid}, missing settings.')
            return

        if capture_settings := self.lookyloo.get_capture_settings(capture_uuid):
            monitor_settings.capture_settings = capture_settings
        else:
            self.logger.warning(f'Unable to monitor {capture_uuid}, missing capture settings.')
            return
        try:
            monitoring_uuid = self.lookyloo.monitoring.monitor(monitor_capture_settings=monitor_settings)
            if isinstance(monitoring_uuid, dict):
                # error message
                self.logger.warning(f'Unable to trigger monitoring: {monitoring_uuid["message"]}')
                return
            with (path / 'monitor_uuid').open('w') as f:
                f.write(monitoring_uuid)
        except Exception as e:
            self.logger.warning(f'Unable to trigger monitoring for {capture_uuid}: {e}')
        else:
            self.logger.info(f'Monitoring for {capture_uuid} enabled.')

    def _auto_trigger(self, path: Path) -> None:
        if (path / 'auto_report').exists():
            # the pickle was built somewhere else, trigger report.
            self.__auto_report(path)
        if (path / 'monitor_capture').exists():
            # the pickle was built somewhere else, trigger monitoring.
            self.__auto_monitor(path)

    def _to_run_forever(self) -> None:
        if self._build_missing_pickles():
            # done with the backlog, trigger a bunch from the lazy queue
            for uuid in self.redis.spop('lazy_background_build', 50):
                try:
                    self.__build_pickle(uuid=str(uuid))
                except LookylooException as e:
                    self.logger.warning(e)
                except Exception as e:
                    self.logger.error(e)
        # Don't need the cache in this class.
        self.lookyloo.clear_tree_cache()

    def _wait_to_finish(self) -> None:
        self.redis.close()
        super()._wait_to_finish()

    def __build_pickle(self, *, uuid: str | None = None, path: str | Path | None = None) -> bool:
        if uuid:
            if s_path := self.redis.hget('lookup_dirs', uuid):
                path = Path(s_path)
                if not path.exists():
                    raise MissingCaptureDirectory(f'Path {path} does not exists')
            elif s_path := self.redis.hget('lookup_dirs_archived', uuid):
                path = Path(s_path)
                if not path.exists():
                    raise MissingCaptureDirectory(f'Path {path} does not exists')
            else:
                raise UUIDMissingInCache(f'Unable to find UUID {uuid} in cache.')
        elif path:
            if isinstance(path, str):
                path = Path(path)
            if not path.exists():
                raise MissingCaptureDirectory(f'Path {path} does not exists')

            with (path / 'uuid').open() as f:
                uuid = f.read()

            if s_path := self.redis.hget(self.lookup_dirs, uuid):
                cached_path = Path(s_path)
                if cached_path != path:
                    # we have a duplicate UUID, it is proably related to some bad copy/paste
                    if cached_path.exists():
                        # Both paths exist, move the one that isn't in lookup_dirs
                        self.logger.critical(f'Duplicate UUID for {uuid} in {cached_path} and {path}, discarding the latest')
                        try:
                            shutil.move(str(path), str(self.discarded_captures_dir / path.name))
                        except FileNotFoundError as e:
                            self.logger.warning(f'Unable to move capture: {e}')
                        raise DuplicateUUID(f'Duplicate UUID for {uuid} in {cached_path} and {path}, discarding the latest')
                    else:
                        # The path in lookup_dirs for that UUID doesn't exists, just update it.
                        self.redis.hset(self.lookup_dirs, uuid, str(path))
            else:
                # The capture with this UUID exists, but it is for some reason missing in lookup_dirs
                self.redis.hset(self.lookup_dirs, uuid, str(path))
        else:
            raise LookylooException('Invalid call, missing UUID and path.')

        if (path / 'auto_report').exists() or (path / 'monitor_capture').exists():
            # if either auto_report or monitor_capture exist, process the capture
            pass
        elif ((path / 'tree.pickle.xz').exists()
                or (path / 'tree.pickle.gz').exists()
                or (path / 'tree.pickle').exists()):
            # We already have a pickle file, and no auto_report / monitor_capture
            return False

        if not list(path.rglob('*.har.gz')) and not list(path.rglob('*.har')):
            # No HAR file
            # junt in case, clear up useless files and skip logging
            (path / 'auto_report').unlink(missing_ok=True)
            (path / 'monitor_capture').unlink(missing_ok=True)
            raise NoValidHarFile(f'{path} has no HAR file.')

        lock_file = path / 'lock'
        if is_locked(path):
            # it is really locked
            raise CaptureLocked(f'{path} is locked, pickle generated by another process.')
        if try_make_file(lock_file):
            with lock_file.open('w') as f:
                f.write(f"{datetime.now().isoformat()};{os.getpid()}")
        else:
            # race condition
            raise CaptureLocked(f'{path} is locked, pickle generated by another process.')

        try:
            self.logger.info(f'Build pickle for {uuid}: {path.name}')
            cache = self.lookyloo.capture_cache(uuid)

            if self.build_recent:
                # only trigger modules for new captures
                try:
                    self.lookyloo.trigger_modules(uuid, auto_trigger=True, force=False, as_admin=False)
                except Exception as e:
                    self.logger.warning(f'Unable to trigger modules for {uuid}: {e}')
                # Trigger whois request on all nodes
                for node in cache.tree.root_hartree.hostname_tree.traverse():
                    try:
                        self.lookyloo.uwhois.query_whois_hostnode(node)
                    except Exception as e:
                        self.logger.info(f'Unable to query whois for {node.name}: {e}')
                # Monitor & auto report, to that last.
                self._auto_trigger(path)

            self.logger.info(f'Pickle for {uuid} built.')
            self.max_captures -= 1
            return True
        except UUIDMissingInCache:
            raise UUIDMissingInCache(f'Unable to find {uuid} in the cache. That should not happen.')
        except NoValidHarFile as e:
            raise TreeBuildFailed(f'HAR files in the capture are unusable {uuid}: {path.name}') from e
        except TreeNeedsRebuild as e:
            raise TreeBuildFailed(f'There are unusable HAR files in the capture {uuid}: {path.name}') from e
        except FileNotFoundError as e:
            raise TreeBuildFailed(f'Capture {uuid} disappeared during processing, probably archived.') from e
        except Exception as e:
            self.logger.exception(f'Unable to build pickle for {uuid}: {path.name}')
            # The capture is not working, moving it away.
            try:
                shutil.move(str(path), str(self.discarded_captures_dir / path.name))
                self.redis.hdel(self.lookup_dirs, uuid)
            except FileNotFoundError as f_e:
                self.logger.warning(f'Unable to move capture: {f_e}')
            raise TreeBuildFailed(f'Building the tree {uuid} ({path.name}) failed for an unexpected reason.') from e
        finally:
            # Should already have been removed by now, but if something goes poorly, remove it here too
            lock_file.unlink(missing_ok=True)

    def _build_missing_pickles(self) -> bool:
        self.logger.debug('Build missing pickles...')
        # Sometimes, we have a huge backlog and the process might get stuck on old captures for a very long time
        # This value makes sure we break out of the loop and build pickles of the most recent captures

        if self.build_recent:
            self.max_captures = 50
        else:
            self.max_captures = 500

        # Initialize time where we do not want to build the pickles anymore.
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval)
        for month_dir in make_dirs_list(self.captures_dir):
            __counter_shutdown = 0
            __counter_shutdown_force = 0
            for _, path in sorted(get_sorted_captures_from_disk(month_dir, cut_time=cut_time,
                                                                keep_more_recent=self.build_recent),
                                  reverse=True):
                __counter_shutdown_force += 1
                if __counter_shutdown_force % 1000 == 0 and self.shutdown_requested():
                    self.logger.warning('Shutdown requested, breaking.')
                    return False

                try:
                    if self.__build_pickle(path=path):
                        __counter_shutdown += 1
                except NoValidHarFile as e:
                    # Nothing to build
                    self.logger.debug(e)
                except CaptureLocked as e:
                    self.logger.debug(e)
                except UUIDMissingInCache as e:
                    self.logger.info(e)
                except MissingCaptureDirectory as e:
                    self.logger.warning(e)
                except DuplicateUUID as e:
                    self.logger.error(e)
                except TreeBuildFailed as e:
                    self.logger.error(e)

                if __counter_shutdown % 10 == 0 and self.shutdown_requested():
                    self.logger.warning('Shutdown requested, breaking.')
                    return False
                if self.max_captures <= 0:
                    self.logger.info('Too many captures in the backlog, start from the beginning.')
                    return False
            if self.shutdown_requested():
                # just in case.
                return False
        self.logger.info('Finished building all missing pickles.')
        return True


def main() -> None:
    i = BackgroundBuildCaptures()
    i.run(sleep_in_sec=60)


def main_archives() -> None:
    i = BackgroundBuildCaptures(recent_only=False)
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
