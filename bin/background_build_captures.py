#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import logging.config
import shutil

from datetime import datetime, timedelta
from pathlib import Path

from redis import Redis

from lookyloo import Lookyloo
from lookyloo.default import AbstractManager, get_config, get_socket_path
from lookyloo.exceptions import MissingUUID, NoValidHarFile, TreeNeedsRebuild
from lookyloo.helpers import is_locked, get_sorted_captures_from_disk, make_dirs_list, get_captures_dir


logging.config.dictConfig(get_config('logging'))


class BackgroundBuildCaptures(AbstractManager):

    def __init__(self, loglevel: int | None=None):
        super().__init__(loglevel)
        self.lookyloo = Lookyloo(cache_max_size=1)
        self.script_name = 'background_build_captures'
        # make sure discarded captures dir exists
        self.captures_dir = get_captures_dir()
        self.discarded_captures_dir = self.captures_dir.parent / 'discarded_captures'
        self.discarded_captures_dir.mkdir(parents=True, exist_ok=True)

        # Redis connector so we don't use the one from Lookyloo
        self.redis = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)

    def __auto_report(self, path: Path) -> None:
        with (path / 'uuid').open() as f:
            capture_uuid = f.read()
        self.logger.info(f'Triggering autoreport for {capture_uuid}...')
        settings = {}
        with (path / 'auto_report').open() as f:
            if ar := f.read():
                # could be an empty file.
                settings = json.loads(ar)
        try:
            self.lookyloo.send_mail(capture_uuid, as_admin=True, email=settings.get('email', ''),
                                    comment=settings.get('comment'))
            (path / 'auto_report').unlink()
        except Exception as e:
            self.logger.warning(f'Unable to send auto report for {capture_uuid}: {e}')
        else:
            self.logger.info(f'Auto report for {capture_uuid} sent.')

    def _to_run_forever(self) -> None:
        self._build_missing_pickles()
        # Don't need the cache in this class.
        self.lookyloo.clear_tree_cache()

    def _wait_to_finish(self) -> None:
        self.redis.close()
        super()._wait_to_finish()

    def _build_missing_pickles(self) -> bool:
        self.logger.debug('Build missing pickles...')
        # Sometimes, we have a huge backlog and the process might get stuck on old captures for a very long time
        # This value makes sure we break out of the loop and build pickles of the most recent captures
        max_captures = 50
        got_new_captures = False

        # Initialize time where we do not want to build the pickles anymore.
        archive_interval = timedelta(days=get_config('generic', 'archive'))
        cut_time = (datetime.now() - archive_interval)
        for month_dir in make_dirs_list(self.captures_dir):
            __counter_shutdown = 0
            for capture_time, path in sorted(get_sorted_captures_from_disk(month_dir, cut_time=cut_time, keep_more_recent=True), reverse=True):
                __counter_shutdown += 1
                if __counter_shutdown % 10 and self.shutdown_requested():
                    self.logger.warning('Shutdown requested, breaking.')
                    return False
                if ((path / 'tree.pickle.gz').exists() or (path / 'tree.pickle').exists()):
                    # We already have a pickle file
                    # self.logger.debug(f'{path} has a pickle.')
                    if (path / 'auto_report').exists():
                        # the pickle was built somewhere else, trigger report.
                        self.__auto_report(path)
                    continue
                if not list(path.rglob('*.har.gz')) and not list(path.rglob('*.har')):
                    # No HAR file
                    self.logger.debug(f'{path} has no HAR file.')
                    continue

                if is_locked(path):
                    # it is really locked
                    self.logger.debug(f'{path} is locked, pickle generated by another process.')
                    continue

                with (path / 'uuid').open() as f:
                    uuid = f.read()

                if not self.redis.hexists('lookup_dirs', uuid):
                    # The capture with this UUID exists, but it is for some reason missing in lookup_dirs
                    self.redis.hset('lookup_dirs', uuid, str(path))
                else:
                    cached_path = Path(self.redis.hget('lookup_dirs', uuid))  # type: ignore[arg-type]
                    if cached_path != path:
                        # we have a duplicate UUID, it is proably related to some bad copy/paste
                        if cached_path.exists():
                            # Both paths exist, move the one that isn't in lookup_dirs
                            self.logger.critical(f'Duplicate UUID for {uuid} in {cached_path} and {path}, discarding the latest')
                            try:
                                shutil.move(str(path), str(self.discarded_captures_dir / path.name))
                            except FileNotFoundError as e:
                                self.logger.warning(f'Unable to move capture: {e}')
                            continue
                        else:
                            # The path in lookup_dirs for that UUID doesn't exists, just update it.
                            self.redis.hset('lookup_dirs', uuid, str(path))

                try:
                    self.logger.info(f'Build pickle for {uuid}: {path.name}')
                    ct = self.lookyloo.get_crawled_tree(uuid)
                    try:
                        self.lookyloo.trigger_modules(uuid, auto_trigger=True, force=False, as_admin=False)
                    except Exception as e:
                        self.logger.warning(f'Unable to trigger modules for {uuid}: {e}')
                    # Trigger whois request on all nodes
                    for node in ct.root_hartree.hostname_tree.traverse():
                        try:
                            self.lookyloo.uwhois.query_whois_hostnode(node)
                        except Exception as e:
                            self.logger.info(f'Unable to query whois for {node.name}: {e}')
                    self.logger.info(f'Pickle for {uuid} built.')
                    got_new_captures = True
                    max_captures -= 1
                    if (path / 'auto_report').exists():
                        self.__auto_report(path)
                except MissingUUID:
                    self.logger.warning(f'Unable to find {uuid}. That should not happen.')
                except NoValidHarFile as e:
                    self.logger.critical(f'There are no HAR files in the capture {uuid}: {path.name} - {e}')
                except TreeNeedsRebuild as e:
                    self.logger.critical(f'There are unusable HAR files in the capture {uuid}: {path.name} - {e}')
                except FileNotFoundError:
                    self.logger.warning(f'Capture {uuid} disappeared during processing, probably archived.')
                except Exception:
                    self.logger.exception(f'Unable to build pickle for {uuid}: {path.name}')
                    # The capture is not working, moving it away.
                    try:
                        shutil.move(str(path), str(self.discarded_captures_dir / path.name))
                        self.redis.hdel('lookup_dirs', uuid)
                    except FileNotFoundError as e:
                        self.logger.warning(f'Unable to move capture: {e}')
                        continue
                if max_captures <= 0:
                    self.logger.info('Too many captures in the backlog, start from the beginning.')
                    return False
        if got_new_captures:
            self.logger.info('Finished building all missing pickles.')
            # Only return True if we built new pickles.
            return True
        return False


def main() -> None:
    i = BackgroundBuildCaptures()
    i.run(sleep_in_sec=60)


if __name__ == '__main__':
    main()
