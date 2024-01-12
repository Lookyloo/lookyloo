#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import logging
import logging.config
import os
import signal
import time
from abc import ABC
from datetime import datetime, timedelta
from subprocess import Popen

from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from .helpers import get_socket_path, get_config


class AbstractManager(ABC):

    script_name: str

    def __init__(self, loglevel: int | None=None):
        self.loglevel: int = loglevel if loglevel is not None else get_config('generic', 'loglevel') or logging.INFO
        self.logger = logging.getLogger(f'{self.__class__.__name__}')
        self.logger.setLevel(self.loglevel)
        self.logger.info(f'Initializing {self.__class__.__name__}')
        self.process: Popen | None = None  # type: ignore[type-arg]
        self.__redis = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)

        self.force_stop = False

    @staticmethod
    def is_running() -> list[tuple[str, float]]:
        try:
            r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
            for script_name, score in r.zrangebyscore('running', '-inf', '+inf', withscores=True):
                for pid in r.smembers(f'service|{script_name}'):
                    try:
                        os.kill(int(pid), 0)
                    except OSError:
                        print(f'Got a dead script: {script_name} - {pid}')
                        r.srem(f'service|{script_name}', pid)
                        other_same_services = r.scard(f'service|{script_name}')
                        if other_same_services:
                            r.zadd('running', {script_name: other_same_services})
                        else:
                            r.zrem('running', script_name)
            return r.zrangebyscore('running', '-inf', '+inf', withscores=True)
        except RedisConnectionError:
            print('Unable to connect to redis, the system is down.')
            return []

    @staticmethod
    def clear_running() -> None:
        try:
            r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
            r.delete('running')
        except RedisConnectionError:
            print('Unable to connect to redis, the system is down.')

    @staticmethod
    def force_shutdown() -> None:
        try:
            r = Redis(unix_socket_path=get_socket_path('cache'), db=1, decode_responses=True)
            r.set('shutdown', 1)
        except RedisConnectionError:
            print('Unable to connect to redis, the system is down.')

    def set_running(self, number: int | None=None) -> None:
        if number == 0:
            self.__redis.zrem('running', self.script_name)
        else:
            if number is None:
                self.__redis.zincrby('running', 1, self.script_name)
            else:
                self.__redis.zadd('running', {self.script_name: number})
            self.__redis.sadd(f'service|{self.script_name}', os.getpid())

    def unset_running(self) -> None:
        current_running = self.__redis.zincrby('running', -1, self.script_name)
        if int(current_running) <= 0:
            self.__redis.zrem('running', self.script_name)

    def long_sleep(self, sleep_in_sec: int, shutdown_check: int=10) -> bool:
        shutdown_check = min(sleep_in_sec, shutdown_check)
        sleep_until = datetime.now() + timedelta(seconds=sleep_in_sec)
        while sleep_until > datetime.now():
            time.sleep(shutdown_check)
            if self.shutdown_requested():
                return False
        return True

    async def long_sleep_async(self, sleep_in_sec: int, shutdown_check: int=10) -> bool:
        shutdown_check = min(sleep_in_sec, shutdown_check)
        sleep_until = datetime.now() + timedelta(seconds=sleep_in_sec)
        while sleep_until > datetime.now():
            await asyncio.sleep(shutdown_check)
            if self.shutdown_requested():
                return False
        return True

    def shutdown_requested(self) -> bool:
        try:
            return bool(self.__redis.exists('shutdown'))
        except ConnectionRefusedError:
            return True
        except RedisConnectionError:
            return True

    def _to_run_forever(self) -> None:
        raise NotImplementedError('This method must be implemented by the child')

    def _kill_process(self) -> None:
        if self.process is None:
            return
        kill_order = [signal.SIGWINCH, signal.SIGTERM, signal.SIGINT, signal.SIGKILL]
        for sig in kill_order:
            if self.process.poll() is None:
                self.logger.info(f'Sending {sig} to {self.process.pid}.')
                self.process.send_signal(sig)
                time.sleep(1)
            else:
                break
        else:
            self.logger.warning(f'Unable to kill {self.process.pid}, keep sending SIGKILL')
            while self.process.poll() is None:
                self.process.send_signal(signal.SIGKILL)
                time.sleep(1)

    def run(self, sleep_in_sec: int) -> None:
        self.logger.info(f'Launching {self.__class__.__name__}')
        try:
            while not self.force_stop:
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
                except Exception:  # nosec B110
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
            self._wait_to_finish()
            if self.process:
                self._kill_process()
            try:
                self.unset_running()
            except Exception:  # nosec B110
                # the services can already be down at that point.
                pass
            self.logger.info(f'Shutting down {self.__class__.__name__}')

    def _wait_to_finish(self) -> None:
        self.logger.info('Not implemented, nothing to wait for.')

    async def stop(self) -> None:
        self.force_stop = True

    async def _to_run_forever_async(self) -> None:
        raise NotImplementedError('This method must be implemented by the child')

    async def _wait_to_finish_async(self) -> None:
        self.logger.info('Not implemented, nothing to wait for.')

    async def stop_async(self) -> None:
        """Method to pass the signal handler:
            loop.add_signal_handler(signal.SIGTERM, lambda: loop.create_task(p.stop()))
        """
        self.force_stop = True

    async def run_async(self, sleep_in_sec: int) -> None:
        self.logger.info(f'Launching {self.__class__.__name__}')
        try:
            while not self.force_stop:
                if self.shutdown_requested():
                    break
                try:
                    if self.process:
                        if self.process.poll() is not None:
                            self.logger.critical(f'Unable to start {self.script_name}.')
                            break
                    else:
                        self.set_running()
                        await self._to_run_forever_async()
                except Exception:  # nosec B110
                    self.logger.exception(f'Something went terribly wrong in {self.__class__.__name__}.')
                finally:
                    if not self.process:
                        # self.process means we run an external script, all the time,
                        # do not unset between sleep.
                        self.unset_running()
                if not await self.long_sleep_async(sleep_in_sec):
                    break
        except KeyboardInterrupt:
            self.logger.warning(f'{self.script_name} killed by user.')
        except Exception as e:  # nosec B110
            self.logger.exception(e)
        finally:
            await self._wait_to_finish_async()
            if self.process:
                self._kill_process()
            try:
                self.unset_running()
            except Exception:  # nosec B110
                # the services can already be down at that point.
                pass
            self.logger.info(f'Shutting down {self.__class__.__name__}')
