#!/usr/bin/env python3

import asyncio
import json
import logging
import signal
import time

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Union

from lacuscore import LacusCore, CaptureStatus as CaptureStatusCore, CaptureResponse as CaptureResponseCore
from pylacus import CaptureStatus as CaptureStatusPy, CaptureResponse as CaptureResponsePy

from lookyloo.lookyloo import Lookyloo
from lookyloo.default import AbstractManager, get_config, safe_create_dir
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
        self.lookyloo = Lookyloo()

        self.captures: Dict[asyncio.Task, float] = {}

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
        entries: Union[CaptureResponseCore, CaptureResponsePy]
        if isinstance(self.lookyloo.lacus, LacusCore):
            if uuid := await self.lookyloo.lacus.consume_queue():
                entries = self.lookyloo.lacus.get_capture(uuid, decode=True)
                if entries['status'] != CaptureStatusCore.DONE:
                    self.logger.warning(f'The capture {uuid} is reported as not done ({entries["status"]}) when it should.')
                    self.lookyloo.redis.zrem('to_capture', uuid)
                    self.lookyloo.redis.delete(uuid)
        else:
            # Find a capture that is done
            try:
                for uuid in self.lookyloo.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf'):
                    if not uuid:
                        break
                    entries = self.lookyloo.lacus.get_capture(uuid)
                    if entries['status'] == CaptureStatusPy.DONE:
                        log = f'Got the capture for {uuid} from Lacus'
                        if runtime := entries.get('runtime'):
                            log = f'{log} - Runtime: {runtime}'
                        self.logger.info(log)
                        break
                else:
                    # No captures are ready
                    uuid = None
            except Exception as e:
                self.logger.critical(f'Error when getting captures from lacus, will retry later: {e}')
                uuid = None
                await asyncio.sleep(10)

        if uuid is None:
            self.unset_running()
            return

        self.lookyloo.redis.sadd('ongoing', uuid)
        queue: Optional[str] = self.lookyloo.redis.getdel(f'{uuid}_mgmt')

        to_capture: Dict[str, str] = self.lookyloo.redis.hgetall(uuid)

        if get_config('generic', 'default_public'):
            # By default, the captures are on the index, unless the user mark them as un-listed
            listing = False if ('listing' in to_capture and to_capture['listing'].lower() in ['false', '0', '']) else True
        else:
            # By default, the captures are not on the index, unless the user mark them as listed
            listing = True if ('listing' in to_capture and to_capture['listing'].lower() in ['true', '1']) else False

        now = datetime.now()
        dirpath = self.capture_dir / str(now.year) / f'{now.month:02}' / now.isoformat()
        safe_create_dir(dirpath)

        if 'os' in to_capture or 'browser' in to_capture:
            meta: Dict[str, str] = {}
            if 'os' in to_capture:
                meta['os'] = to_capture['os']
            if 'browser' in to_capture:
                meta['browser'] = to_capture['browser']
            with (dirpath / 'meta').open('w') as _meta:
                json.dump(meta, _meta)

        # Write UUID
        with (dirpath / 'uuid').open('w') as _uuid:
            _uuid.write(uuid)

        # Write no_index marker (optional)
        if not listing:
            (dirpath / 'no_index').touch()

        # Write parent UUID (optional)
        if 'parent' in to_capture:
            with (dirpath / 'parent').open('w') as _parent:
                _parent.write(to_capture['parent'])

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

        lazy_cleanup = self.lookyloo.redis.pipeline()
        lazy_cleanup.hset('lookup_dirs', uuid, str(dirpath))
        if queue and self.lookyloo.redis.zscore('queues', queue):
            lazy_cleanup.zincrby('queues', -1, queue)
        lazy_cleanup.zrem('to_capture', uuid)
        lazy_cleanup.srem('ongoing', uuid)
        lazy_cleanup.delete(uuid)
        # make sure to expire the key if nothing was processed for a while (= queues empty)
        lazy_cleanup.expire('queues', 600)
        lazy_cleanup.execute()
        self.unset_running()
        self.logger.info(f'Done with {uuid}')

    async def cancel_old_captures(self):
        cancelled_tasks = []
        for task, timestamp in self.captures.items():
            if time.time() - timestamp >= get_config('generic', 'max_capture_time'):
                task.cancel()
                cancelled_tasks.append(task)
                self.logger.warning('A capture has been going for too long, canceling it.')
        if cancelled_tasks:
            await asyncio.gather(*cancelled_tasks, return_exceptions=True)

    async def _to_run_forever_async(self):
        await self.cancel_old_captures()
        if self.force_stop:
            return
        capture = asyncio.create_task(self.process_capture_queue())
        self.captures[capture] = time.time()
        capture.add_done_callback(self.captures.pop)
        while len(self.captures) >= get_config('generic', 'async_capture_processes'):
            await self.cancel_old_captures()
            await asyncio.sleep(1)

    async def _wait_to_finish(self):
        while self.captures:
            self.logger.info(f'Waiting for {len(self.captures)} capture(s) to finish...')
            await asyncio.sleep(5)
        self.logger.info('No more captures')


def main():
    m = AsyncCapture()

    loop = asyncio.new_event_loop()
    loop.add_signal_handler(signal.SIGTERM, lambda: loop.create_task(m.stop_async()))

    try:
        loop.run_until_complete(m.run_async(sleep_in_sec=1))
    finally:
        loop.close()


if __name__ == '__main__':
    main()
