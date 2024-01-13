#!/usr/bin/env python3

from __future__ import annotations

import logging
import logging.config

from subprocess import Popen

from lookyloo.default import get_config, get_homedir, AbstractManager

logging.config.dictConfig(get_config('logging'))


class Website(AbstractManager):

    def __init__(self, loglevel: int | None=None) -> None:
        super().__init__(loglevel)
        self.script_name = 'website'
        self.process: Popen = self._launch_website()  # type: ignore[type-arg]
        self.set_running()

    def _launch_website(self) -> Popen:  # type: ignore[type-arg]
        website_dir = get_homedir() / 'website'
        ip = get_config('generic', 'website_listen_ip')
        port = get_config('generic', 'website_listen_port')
        return Popen(['gunicorn', '-w', '10',
                      '--graceful-timeout', '2', '--timeout', '300',
                      '-b', f'{ip}:{port}',
                      '--log-level', 'info',
                      '--max-requests', '10000',
                      'web:app'],
                     cwd=website_dir)


def main() -> None:
    w = Website()
    w.run(sleep_in_sec=10)


if __name__ == '__main__':
    main()
