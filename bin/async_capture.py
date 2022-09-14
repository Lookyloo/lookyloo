#!/usr/bin/env python3

import asyncio
import json
import logging

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lacuscore import LacusCore
from redis.asyncio import Redis
from redis import Redis as RedisSync

from lookyloo.default import AbstractManager, get_config, get_socket_path, safe_create_dir
from lookyloo.helpers import get_captures_dir, UserAgents, CaptureStatus

from lookyloo.modules import FOX

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s:%(message)s',
                    level=logging.INFO)


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int=logging.INFO):
        super().__init__(loglevel)
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.user_agents = UserAgents()
        self.redis_sync: RedisSync = RedisSync(unix_socket_path=get_socket_path('cache'))
        self.lacus = LacusCore(self.redis_sync)

        self.fox = FOX(get_config('modules', 'FOX'))
        if not self.fox.available:
            self.logger.warning('Unable to setup the FOX module')

    def thirdparty_submit(self, url: str) -> None:
        if self.fox.available:
            self.fox.capture_default_trigger(url, auto_trigger=True)

    async def process_capture_queue(self) -> None:
        '''Process a query from the capture queue'''
        value: List[Tuple[bytes, float]] = await self.redis.zpopmax('to_capture')
        if not value or not value[0]:
            # The queue was consumed by an other process.
            return
        uuid: str = value[0][0].decode()
        queue: Optional[bytes] = await self.redis.getdel(f'{uuid}_mgmt')
        await self.redis.sadd('ongoing', uuid)

        to_capture: Dict[bytes, bytes] = await self.redis.hgetall(uuid)

        if get_config('generic', 'default_public'):
            # By default, the captures are on the index, unless the user mark them as un-listed
            listing = False if (b'listing' in to_capture and to_capture[b'listing'].lower() in [b'false', b'0', b'']) else True
        else:
            # By default, the captures are not on the index, unless the user mark them as listed
            listing = True if (b'listing' in to_capture and to_capture[b'listing'].lower() in [b'true', b'1']) else False

        await self.lacus.capture(uuid)

        while True:
            entries = self.lacus.get_capture(uuid, decode=True)
            if entries['status'] == CaptureStatus.DONE.value:
                break
            elif entries['status'] == CaptureStatus.UNKNOWN.value:
                self.logger.warning(f'Unable to find {uuid}.')
                break
            elif entries['status'] == CaptureStatus.QUEUED.value:
                self.logger.info(f'{uuid} is in the queue.')
                await asyncio.sleep(5)
            elif entries['status'] == CaptureStatus.ONGOING.value:
                self.logger.info(f'{uuid} is ongoing.')
                await asyncio.sleep(5)
            else:
                self.logger.warning(f'{entries["status"]} is not a valid status')
                break

        if not entries:
            # broken
            self.logger.critical(f'Something went terribly wrong when capturing {uuid}.')
        else:
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
            await self.redis.hset('lookup_dirs', uuid, str(dirpath))

        async with self.redis.pipeline() as lazy_cleanup:
            if queue and await self.redis.zscore('queues', queue):
                await lazy_cleanup.zincrby('queues', -1, queue)
            await lazy_cleanup.srem('ongoing', uuid)
            await lazy_cleanup.delete(uuid)
            # make sure to expire the key if nothing was processed for a while (= queues empty)
            await lazy_cleanup.expire('queues', 600)
            await lazy_cleanup.execute()

    async def _to_run_forever_async(self):
        self.redis: Redis = Redis(unix_socket_path=get_socket_path('cache'))
        while await self.redis.exists('to_capture'):
            await self.process_capture_queue()
            if self.shutdown_requested():
                break
        await self.redis.close()


def main():
    m = AsyncCapture()
    asyncio.run(m.run_async(sleep_in_sec=1))


if __name__ == '__main__':
    main()
