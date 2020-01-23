#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import signal
from subprocess import Popen
from lookyloo.helpers import get_homedir, shutdown_requested, set_running, unset_running, get_socket_path
from redis import StrictRedis


if __name__ == '__main__':
    r = StrictRedis(unix_socket_path=get_socket_path('cache'))
    r.delete('cache_loaded')
    website_dir = get_homedir() / 'website'
    Popen([str(website_dir / '3rdparty.sh')], cwd=website_dir)
    try:
        p = Popen(['gunicorn','-w', '10',
                   '--graceful-timeout', '2', '--timeout', '300',
                   '-b', '0.0.0.0:5100',
                   '--log-level', 'info',
                   'web:app'],
                  cwd=website_dir)
        set_running('website')
        while True:
            if shutdown_requested() or p.poll() is not None:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print('Website killed by user.')
    finally:
        print('Shutting down website.')
        try:
            # Killing everything if possible.
            p.send_signal(signal.SIGWINCH)
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
        unset_running('website')
