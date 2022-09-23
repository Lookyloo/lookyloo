#!/usr/bin/env python3

import asyncio
import json
import logging

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set, Union

from lacuscore import LacusCore, CaptureStatus as CaptureStatusCore
from pylacus import PyLacus, CaptureStatus as CaptureStatusPy
from redis import Redis

from lookyloo.default import AbstractManager, get_config, get_socket_path, safe_create_dir
from lookyloo.helpers import get_captures_dir

from lookyloo.modules import FOX

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'))

        self.lacus: Union[PyLacus, LacusCore]
        has_remote_lacus = False
        if get_config('generic', 'remote_lacus'):
            remote_lacus_config = get_config('generic', 'remote_lacus')
            if remote_lacus_config.get('enable'):
                self.logger.info("Remote lacus enabled, trying to set it up...")
                remote_lacus_url = remote_lacus_config.get('url')
                self.lacus = PyLacus(remote_lacus_url)
                if self.lacus.is_up:
                    has_remote_lacus = True
                    self.logger.info(f"Remote lacus enabled to {remote_lacus_url}.")
                else:
                    self.logger.warning(f"Unable to setup remote lacus to {remote_lacus_url}.")

        if not has_remote_lacus:
            self.lacus = LacusCore(self.redis, get_config('generic', 'tor_proxy'),
                                   get_config('generic', 'only_global_lookups'))

        self.captures: Set[asyncio.Task] = set()

        self.fox = FOX(get_config('modules', 'FOX'))
        if not self.fox.available:
            self.logger.warning('Unable to setup the FOX module')

    def thirdparty_submit(self, url: str) -> None:
        if self.fox.available:
            self.fox.capture_default_trigger(url, auto_trigger=True)

    async def process_capture_queue(self) -> None:
        '''Process a query from the capture queue'''
        self.set_running()
        uuid: Optional[str] = None
        if isinstance(self.lacus, LacusCore):
            if uuid := await self.lacus.consume_queue():
                entries = self.lacus.get_capture(uuid, decode=True)
                if entries['status'] != CaptureStatusCore.DONE:
                    self.logger.warning(f'The capture {uuid} is reported as not done ({entries["status"]}) when it should.')
                    self.redis.zrem('to_capture', uuid)
                    self.redis.delete(uuid)
        else:
            # Find a capture that is done
            for uuid_b in self.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf'):
                uuid = uuid_b.decode()
                if not uuid:
                    break
                entries = self.lacus.get_capture(uuid)
                if entries['status'] == CaptureStatusPy.DONE:
                    break

        if uuid is None:
            self.unset_running()
            return

        self.redis.sadd('ongoing', uuid)
        queue: Optional[bytes] = self.redis.getdel(f'{uuid}_mgmt')

        to_capture: Dict[bytes, bytes] = self.redis.hgetall(uuid)

        if get_config('generic', 'default_public'):
            # By default, the captures are on the index, unless the user mark them as un-listed
            listing = False if (b'listing' in to_capture and to_capture[b'listing'].lower() in [b'false', b'0', b'']) else True
        else:
            # By default, the captures are not on the index, unless the user mark them as listed
            listing = True if (b'listing' in to_capture and to_capture[b'listing'].lower() in [b'true', b'1']) else False

        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / now.isoformat()
        safe_create_dir(dirpath)

        if b'os' in to_capture or b'browser' in to_capture:
            meta: Dict[str, str] = {}
            if b'os' in to_capture:
                meta['os'] = to_capture[b'os'].decode()
            if b'browser' in to_capture:
                meta['browser'] = to_capture[b'browser'].decode()
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(uuid)

        # Write no_index marker (optional)
        if not listing:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if b'parent' in to_capture:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(to_capture[b'parent'].decode())

        if 'downloaded_filename' in entries and entries['downloaded_filename']:
            with (dirpath / '0.data.filename').open('w') as _downloaded_filename:
                _downloaded_filename.write(entries['downloaded_filename'])

        if 'downloaded_file' in entries and entries['downloaded_file']:
            with (dirpath / '0.data').open('wb') as _downloaded_file:
                _downloaded_file.write(entries['downloaded_file'])

        if 'error' in entries:
            with (dirpath / 'error.txt').open('w') as _error:
                json.dump(entries['error'], _error)

        if 'har' in entries:
            with (dirpath / '0.har').open('w') as _har:
                json.dump(entries['har'], _har)

        if 'png' in entries and entries['png']:
            with (dirpath / '0.png').open('wb') as _img:
                _img.write(entries['png'])

        if 'html' in entries and entries['html']:
            with (dirpath / '0.html').open('w') as _html:
                _html.write(entries['html'])

        if 'last_redirected_url' in entries and entries['last_redirected_url']:
            with (dirpath / '0.last_redirect.txt').open('w') as _redir:
                _redir.write(entries['last_redirected_url'])

        if 'cookies' in entries and entries['cookies']:
            with (dirpath / '0.cookies.json').open('w') as _cookies:
                json.dump(entries['cookies'], _cookies)

        lazy_cleanup = self.redis.pipeline()
        lazy_cleanup.hset('lookup_dirs', uuid, str(dirpath))
        if queue and self.redis.zscore('queues', queue):
            lazy_cleanup.zincrby('queues', -1, queue)
        lazy_cleanup.zrem('to_capture', uuid)
        lazy_cleanup.srem('ongoing', uuid)
        lazy_cleanup.delete(uuid)
        # make sure to expire the key if nothing was processed for a while (= queues empty)
        lazy_cleanup.expire('queues', 600)
        lazy_cleanup.execute()
        self.unset_running()

    async def _to_run_forever_async(self):
        capture = asyncio.create_task(self.process_capture_queue())
        capture.add_done_callback(self.captures.discard)
        self.captures.add(capture)
        while len(self.captures) >= get_config('generic', 'async_capture_processes'):
            await asyncio.sleep(1)


def main():
    m = AsyncCapture()
    asyncio.run(m.run_async(sleep_in_sec=1))


if __name__ == '__main__':
    main()
