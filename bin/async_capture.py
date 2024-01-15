#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import json
import logging
import logging.config
import signal

from pathlib import Path

from lacuscore import LacusCore, CaptureStatus as CaptureStatusCore, CaptureResponse as CaptureResponseCore
from pylacus import PyLacus, CaptureStatus as CaptureStatusPy, CaptureResponse as CaptureResponsePy

from lookyloo import Lookyloo, CaptureSettings
from lookyloo.default import AbstractManager, get_config
from lookyloo.helpers import get_captures_dir

from lookyloo.modules import FOX

logging.config.dictConfig(get_config('logging'))


class AsyncCapture(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'async_capture'
        self.only_global_lookups: bool = get_config('generic', 'only_global_lookups')
        self.capture_dir: Path = get_captures_dir()
        self.lookyloo = Lookyloo()

        if isinstance(self.lookyloo.lacus, LacusCore):
            self.captures: set[asyncio.Task] = set()  # type: ignore[type-arg]

        self.fox = FOX(config_name='FOX')
        if not self.fox.available:
            self.logger.warning('Unable to setup the FOX module')

    def thirdparty_submit(self, url: str) -> None:
        if self.fox.available:
            self.fox.capture_default_trigger(url, auto_trigger=True)

    async def _trigger_captures(self) -> None:
        # Only called if LacusCore is used
        max_new_captures = get_config('generic', 'async_capture_processes') - len(self.captures)
        self.logger.debug(f'{len(self.captures)} ongoing captures.')
        if max_new_captures <= 0:
            self.logger.info(f'Max amount of captures in parallel reached ({len(self.captures)})')
            return None
        for capture_task in self.lookyloo.lacus.consume_queue(max_new_captures):  # type: ignore[union-attr]
            self.captures.add(capture_task)
            capture_task.add_done_callback(self.captures.discard)

    def uuids_ready(self) -> list[str]:
        return [uuid for uuid in self.lookyloo.redis.zrevrangebyscore('to_capture', 'Inf', '-Inf')
                if uuid and self.lookyloo.lacus.get_capture_status(uuid) in [CaptureStatusPy.DONE, CaptureStatusCore]]

    def process_capture_queue(self) -> None:
        '''Process a query from the capture queue'''
        entries: CaptureResponseCore | CaptureResponsePy
        for uuid in self.uuids_ready():
            if isinstance(self.lookyloo.lacus, LacusCore):
                entries = self.lookyloo.lacus.get_capture(uuid, decode=True)
            elif isinstance(self.lookyloo.lacus, PyLacus):
                entries = self.lookyloo.lacus.get_capture(uuid)
            else:
                raise Exception('Something is broken.')
            log = f'Got the capture for {uuid} from Lacus'
            if runtime := entries.get('runtime'):
                log = f'{log} - Runtime: {runtime}'
            self.logger.info(log)

            self.lookyloo.redis.sadd('ongoing', uuid)
            queue: str | None = self.lookyloo.redis.getdel(f'{uuid}_mgmt')

            to_capture: CaptureSettings = self.lookyloo.redis.hgetall(uuid)  # type: ignore[assignment]

            if get_config('generic', 'default_public'):
                # By default, the captures are on the index, unless the user mark them as un-listed
                listing = False if ('listing' in to_capture and to_capture['listing'].lower() in ['false', '0', '']) else True  # type: ignore
            else:
                # By default, the captures are not on the index, unless the user mark them as listed
                listing = True if ('listing' in to_capture and to_capture['listing'].lower() in ['true', '1']) else False  # type: ignore

            self.lookyloo.store_capture(
                uuid, listing,
                os=to_capture.get('os'), browser=to_capture.get('browser'),
                parent=to_capture.get('parent'),
                downloaded_filename=entries.get('downloaded_filename'),
                downloaded_file=entries.get('downloaded_file'),
                error=entries.get('error'), har=entries.get('har'),
                png=entries.get('png'), html=entries.get('html'),
                last_redirected_url=entries.get('last_redirected_url'),
                cookies=entries.get('cookies'),
                capture_settings=to_capture,
                potential_favicons=entries.get('potential_favicons')
            )

            if 'auto_report' in to_capture:
                settings = {}
                if isinstance(to_capture['auto_report'], str):
                    if to_capture['auto_report'].isdigit():
                        # auto_report was a bool in the submission, it can be 1 or 0. 0 means no.
                        if to_capture['auto_report'] == '0':
                            continue
                    else:
                        settings = json.loads(to_capture['auto_report'])
                elif isinstance(to_capture['auto_report'], dict):
                    settings = to_capture['auto_report']

                self.lookyloo.send_mail(uuid, email=settings.get('email', ''),
                                        comment=settings.get('comment'))

            lazy_cleanup = self.lookyloo.redis.pipeline()
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

    async def _to_run_forever_async(self) -> None:
        if self.force_stop:
            return None

        if isinstance(self.lookyloo.lacus, LacusCore):
            await self._trigger_captures()
            # NOTE: +1 because running this method also counts for one and will
            #       be decremented when it finishes
            self.set_running(len(self.captures) + 1)

        self.process_capture_queue()

    async def _wait_to_finish_async(self) -> None:
        if isinstance(self.lookyloo.lacus, LacusCore):
            while self.captures:
                self.logger.info(f'Waiting for {len(self.captures)} capture(s) to finish...')
                await asyncio.sleep(5)
                # NOTE: +1 so we don't quit before the final process capture queue
                self.set_running(len(self.captures) + 1)
            self.process_capture_queue()
            self.unset_running()
        self.logger.info('No more captures')


def main() -> None:
    m = AsyncCapture()

    loop = asyncio.new_event_loop()
    loop.add_signal_handler(signal.SIGTERM, lambda: loop.create_task(m.stop_async()))

    try:
        loop.run_until_complete(m.run_async(sleep_in_sec=1))
    finally:
        loop.close()


if __name__ == '__main__':
    main()
