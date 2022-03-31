#!/usr/bin/env python3

import logging
import signal
import time
from abc import ABC
from datetime import datetime, timedelta
from subprocess import Popen
from typing import List, Optional, Tuple

from redis import Redis
from redis.exceptions import ConnectionError

from .helpers import get_socket_path


class AbstractManager(ABC):

    script_name: str

    def __init__(self, loglevel: int=logging.DEBUG):
        self.loglevel = loglevel
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(loglevel)
        self.logger.info(f'Initializing {self.__class__.__name__}')
        self.process: Optional[Popen] = None
        self.__redis = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)

    @staticmethod
    def is_running() -> List[Tuple[str, float]]:
        try:
            r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
            return r.zrangebyscore('running', '-inf', '+inf', withscores=True)
        except ConnectionError:
            print('Unable to connect to redis, the system is down.')
            return []

    @staticmethod
    def force_shutdown():
        try:
            r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
            r.set('shutdown', 1)
        except ConnectionError:
            print('Unable to connect to redis, the system is down.')

    def set_running(self) -> None:
        self.__redis.zincrby('running', 1, self.script_name)

    def unset_running(self) -> None:
        current_running = self.__redis.zincrby('running', -1, self.script_name)
        if int(current_running) <= 0:
            self.__redis.zrem('running', self.script_name)

    def long_sleep(self, sleep_in_sec: int, shutdown_check: int=10) -> bool:
        if shutdown_check > sleep_in_sec:
            shutdown_check = sleep_in_sec
        sleep_until = datetime.now() + timedelta(seconds=sleep_in_sec)
        while sleep_until > datetime.now():
            time.sleep(shutdown_check)
            if self.shutdown_requested():
                return False
        return True

    def shutdown_requested(self) -> bool:
        try:
            return True if self.__redis.exists('shutdown') else False
        except ConnectionRefusedError:
            return True
        except ConnectionError:
            return True

    async def _to_run_forever_async(self) -> None:
        pass

    def _to_run_forever(self) -> None:
        pass

    def run(self, sleep_in_sec: int) -> None:
        self.logger.info(f'Launching {self.__class__.__name__}')
        try:
            while True:
                if self.shutdown_requested():
                    break
                try:
                    if self.process:
                        if self.process.poll() is not None:
                            self.logger.critical(f'Unable to start {self.script_name}.')
                            break
                    else:
                        self.set_running()
                        self._to_run_forever()
                except Exception:
                    self.logger.exception(f'Something went terribly wrong in {self.__class__.__name__}.')
                finally:
                    if not self.process:
                        # self.process means we run an external script, all the time,
                        # do not unset between sleep.
                        self.unset_running()
                if not self.long_sleep(sleep_in_sec):
                    break
        except KeyboardInterrupt:
            self.logger.warning(f'{self.script_name} killed by user.')
        finally:
            if self.process:
                try:
                    # Killing everything if possible.
                    self.process.send_signal(signal.SIGWINCH)
                    self.process.send_signal(signal.SIGTERM)
                except Exception:
                    pass
            try:
                self.unset_running()
            except Exception:
                # the services can already be down at that point.
                pass
            self.logger.info(f'Shutting down {self.__class__.__name__}')
