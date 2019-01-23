#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from lookyloo.helpers import get_homedir

if __name__ == '__main__':
    website_dir = get_homedir()
    Popen([str(website_dir / '3rdparty.sh')], cwd=website_dir)
    try:
        Popen(['gunicorn', '--worker-class', 'eventlet', '-w', '10', '-b', '0.0.0.0:5100', 'lookyloo:app'],
              cwd=website_dir).communicate()
    except KeyboardInterrupt:
        print('Stopping gunicorn.')
