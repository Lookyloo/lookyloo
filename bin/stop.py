#!/usr/bin/env python3

from subprocess import Popen, run

from redis import Redis
from redis.exceptions import ConnectionError

from lookyloo.default import get_homedir, get_socket_path


def main():
    get_homedir()
    p = Popen(['shutdown'])
    p.wait()
    try:
        r = Redis(unix_socket_path=get_socket_path('cache'), db=1)
        r.delete('shutdown')
        r = Redis(unix_socket_path=get_socket_path('cache'))
        r.delete('tree_cache')
        print('Shutting down databases...')
        p_backend = run(['run_backend', '--stop'])
        p_backend.check_returncode()
        print('done.')
    except ConnectionError:
        # Already down, skip the stacktrace
        pass


if __name__ == '__main__':
    main()
