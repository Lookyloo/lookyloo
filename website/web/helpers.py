#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

import flask_login  # type: ignore[import-untyped]
from flask import Request
from werkzeug.security import generate_password_hash

from lookyloo import Lookyloo
from lookyloo.default import get_config, get_homedir

__global_lookyloo_instance = None


def get_lookyloo_instance() -> Lookyloo:
    global __global_lookyloo_instance
    if __global_lookyloo_instance is None:
        __global_lookyloo_instance = Lookyloo()
    return __global_lookyloo_instance


def src_request_ip(request: Request) -> str | None:
    # NOTE: X-Real-IP is the IP passed by the reverse proxy in the headers.
    real_ip = request.headers.get('X-Real-IP')
    if not real_ip:
        real_ip = request.remote_addr
    return real_ip


class User(flask_login.UserMixin):  # type: ignore[misc]
    pass


def load_user_from_request(request: Request) -> User | None:
    api_key = request.headers.get('Authorization')
    if not api_key:
        return None
    user = User()
    api_key = api_key.strip()
    keys_table = build_keys_table()
    if api_key in keys_table:
        user.id = keys_table[api_key]
        return user
    return None


@lru_cache(64)
def build_keys_table() -> dict[str, str]:
    keys_table = {}
    for username, authstuff in build_users_table().items():
        if 'authkey' in authstuff:
            keys_table[authstuff['authkey']] = username
    return keys_table


@lru_cache(64)
def get_users() -> dict[str, str | list[str]]:
    try:
        # Use legacy user mgmt, no need to print a warning, and it will fail on new install.
        return get_config('generic', 'cache_clean_user', quiet=True)
    except Exception:
        return get_config('generic', 'users')


@lru_cache(64)
def build_users_table() -> dict[str, dict[str, str]]:
    users_table: dict[str, dict[str, str]] = {}
    for username, authstuff in get_users().items():
        if isinstance(authstuff, str):
            # just a password, make a key
            users_table[username] = {}
            users_table[username]['password'] = generate_password_hash(authstuff)
            users_table[username]['authkey'] = hashlib.pbkdf2_hmac('sha256', get_secret_key(),
                                                                   authstuff.encode(),
                                                                   100000).hex()

        elif isinstance(authstuff, list) and len(authstuff) == 2:
            if isinstance(authstuff[0], str) and isinstance(authstuff[1], str) and len(authstuff[1]) == 64:
                users_table[username] = {}
                users_table[username]['password'] = generate_password_hash(authstuff[0])
                users_table[username]['authkey'] = authstuff[1]
        else:
            raise Exception('User setup invalid. Must be "username": "password" or "username": ["password", "token 64 chars (sha256)"]')
    return users_table


@lru_cache(64)
def get_secret_key() -> bytes:
    secret_file_path: Path = get_homedir() / 'secret_key'
    if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
        if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
            with secret_file_path.open('wb') as f:
                f.write(os.urandom(64))
    with secret_file_path.open('rb') as f:
        return f.read()


@lru_cache(64)
def sri_load() -> dict[str, dict[str, str]]:
    with (get_homedir() / 'website' / 'web' / 'sri.txt').open() as f:
        return json.load(f)
