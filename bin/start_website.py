#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import signal
from subprocess import Popen
from lookyloo.helpers import get_homedir, shutdown_requested, set_running, unset_running

if __name__ == '__main__':
    website_dir = get_homedir() / 'website'
    Popen([str(website_dir / '3rdparty.sh')], cwd=website_dir)
    try:
        p = Popen(['gunicorn', '--worker-class', 'eventlet', '-w', '10', '--graceful-timeout', '2',
                   '-b', '0.0.0.0:5100', 'web:app'],
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
