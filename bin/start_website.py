#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import signal
from subprocess import Popen
from lookyloo.helpers import get_homedir, shutdown_requested, set_running, unset_running, get_socket_path, get_config
from redis import StrictRedis


def main():
    r = StrictRedis(unix_socket_path=get_socket_path('cache'))
    r.delete('cache_loaded')
    website_dir = get_homedir() / 'website'
    ip = get_config('generic', 'website_listen_ip')
    port = get_config('generic', 'website_listen_port')
    try:
        p = Popen(['gunicorn', '-w', '10',
                   '--graceful-timeout', '2', '--timeout', '300',
                   '-b', f'{ip}:{port}',
                   '--log-level', 'info',
                   'web:app'],
                  cwd=website_dir)
        set_running('website')
        while True:
            if p.poll() is not None:
                print('gunicorn stopped itself.')
                break
            if shutdown_requested():
                print('"shutdown" key present in the cache database.')
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


if __name__ == '__main__':
    main()
