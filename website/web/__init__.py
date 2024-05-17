#!/usr/bin/env python3

from __future__ import annotations

import base64
import calendar
import functools
import gzip
import hashlib
import http
import json
import logging
import logging.config
import os
import sys
import time

import filetype  # type: ignore[import-untyped]

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from importlib.metadata import version
from io import BytesIO, StringIO
from typing import Any, TypedDict, Iterable
from urllib.parse import quote_plus, unquote_plus, urlparse
from uuid import uuid4
from zipfile import ZipFile

from har2tree import HostNode, URLNode
import flask_login  # type: ignore[import-untyped]
from flask import (Flask, Response, Request, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)
from flask_bootstrap import Bootstrap5  # type: ignore[import-untyped]
from flask_cors import CORS  # type: ignore[import-untyped]
from flask_restx import Api  # type: ignore[import-untyped]
from lacuscore import CaptureStatus
from puremagic import from_string  # type: ignore[import-untyped]
from pymisp import MISPEvent, MISPServerError  # type: ignore[attr-defined]
from werkzeug.security import check_password_hash
from werkzeug.wrappers.response import Response as WerkzeugResponse

from lookyloo import Lookyloo, CaptureSettings
from lookyloo.default import get_config
from lookyloo.exceptions import MissingUUID, NoValidHarFile, LacusUnreachable
from lookyloo.helpers import get_taxonomies, UserAgents, load_cookies

if sys.version_info < (3, 9):
    from pytz import all_timezones_set
else:
    from zoneinfo import available_timezones
    all_timezones_set = available_timezones()

from .genericapi import api as generic_api
from .helpers import (User, build_users_table, get_secret_key,
                      load_user_from_request, src_request_ip, sri_load,
                      get_lookyloo_instance, get_indexing)
from .proxied import ReverseProxied

logging.config.dictConfig(get_config('logging'))

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore[method-assign]

app.config['SECRET_KEY'] = get_secret_key()

Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.debug = False

pkg_version = version('lookyloo')

# Auth stuff
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# User agents manager
user_agents = UserAgents()


@login_manager.user_loader  # type: ignore[misc]
def user_loader(username: str) -> User | None:
    if username not in build_users_table():
        return None
    user = User()
    user.id = username
    return user


@login_manager.request_loader  # type: ignore[misc]
def _load_user_from_request(request: Request) -> User | None:
    return load_user_from_request(request)


@app.route('/login', methods=['GET', 'POST'])
def login() -> WerkzeugResponse | str | Response:
    if request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='username' id='username' placeholder='username'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               '''

    username = request.form['username']
    users_table = build_users_table()
    if username in users_table and check_password_hash(users_table[username]['password'], request.form['password']):
        user = User()
        user.id = username
        flask_login.login_user(user)
        flash(f'Logged in as: {flask_login.current_user.id}', 'success')
    else:
        flash(f'Unable to login as: {username}', 'error')

    return redirect(url_for('index'))


@app.route('/logout')
@flask_login.login_required  # type: ignore[misc]
def logout() -> WerkzeugResponse:
    flask_login.logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('index'))


# Config

lookyloo: Lookyloo = get_lookyloo_instance()

time_delta_on_index = get_config('generic', 'time_delta_on_index')
blur_screenshot = get_config('generic', 'enable_default_blur_screenshot')

use_own_ua = get_config('generic', 'use_user_agents_users')
enable_mail_notification = get_config('generic', 'enable_mail_notification')
ignore_sri = get_config('generic', 'ignore_sri')
if enable_mail_notification:
    confirm_message = get_config('generic', 'email').get('confirm_message')
else:
    confirm_message = ''
enable_context_by_users = get_config('generic', 'enable_context_by_users')
enable_categorization = get_config('generic', 'enable_categorization')
enable_bookmark = get_config('generic', 'enable_bookmark')
auto_trigger_modules = get_config('generic', 'auto_trigger_modules')
hide_captures_with_error = get_config('generic', 'hide_captures_with_error')


# ##### Global methods passed to jinja

# Method to make sizes in bytes human readable
# Source: https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num: float, suffix: str='B') -> str:
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return ("{:.1f}{}{}".format(num, 'Yi', suffix)).strip()


app.jinja_env.globals.update(sizeof_fmt=sizeof_fmt)


def http_status_description(code: int) -> str:
    if code in http.client.responses:
        return http.client.responses[code]
    return f'Invalid code: {code}'


app.jinja_env.globals.update(http_status_description=http_status_description)


def month_name(month: int) -> str:
    return calendar.month_name[month]


app.jinja_env.globals.update(month_name=month_name)


def get_sri(directory: str, filename: str) -> str:
    if ignore_sri:
        return ""
    sha512 = sri_load()[directory][filename]
    return f'integrity=sha512-{sha512}'


app.jinja_env.globals.update(get_sri=get_sri)


class Icon(TypedDict):
    icon: str
    tooltip: str


def get_icon(icon_id: str) -> Icon | None:
    available_icons: dict[str, Icon] = {
        'js': {'icon': "javascript.png", 'tooltip': 'The content of the response is a javascript'},
        'exe': {'icon': "exe.png", 'tooltip': 'The content of the response is an executable'},
        'css': {'icon': "css.png", 'tooltip': 'The content of the response is a CSS'},
        'font': {'icon': "font.png", 'tooltip': 'The content of the response is a font'},
        'html': {'icon': "html.png", 'tooltip': 'The content of the response is a HTML document'},
        'json': {'icon': "json.png", 'tooltip': 'The content of the response is a Json'},
        'text': {'icon': "json.png", 'tooltip': 'The content of the response is a text'},  # FIXME: Need new icon
        'iframe': {'icon': "ifr.png", 'tooltip': 'This content is loaded from an Iframe'},
        'image': {'icon': "img.png", 'tooltip': 'The content of the response is an image'},
        'unset_mimetype': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is not set'},
        'octet-stream': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is a binary blob'},
        'unknown_mimetype': {'icon': "wtf.png", 'tooltip': 'The type of content of the response is of an unknown type'},
        'video': {'icon': "video.png", 'tooltip': 'The content of the response is a video'},
        'livestream': {'icon': "video.png", 'tooltip': 'The content of the response is a livestream'},
        'response_cookie': {'icon': "cookie_received.png", 'tooltip': 'There are cookies in the response'},
        'request_cookie': {'icon': "cookie_read.png", 'tooltip': 'There are cookies in the request'},
        'redirect': {'icon': "redirect.png", 'tooltip': 'The request is redirected'},
        'redirect_to_nothing': {'icon': "cookie_in_url.png", 'tooltip': 'The request is redirected to an URL we do not have in the capture'}
    }
    return available_icons.get(icon_id)


app.jinja_env.globals.update(get_icon=get_icon)


def get_tz_info() -> tuple[str | None, str, set[str]]:
    now = datetime.now().astimezone()
    local_TZ = now.tzname()
    local_UTC_offset = f'UTC{now.strftime("%z")}'
    return local_TZ, local_UTC_offset, all_timezones_set


app.jinja_env.globals.update(tz_info=get_tz_info)


# ##### Generic/configuration methods #####

@app.after_request
def after_request(response: Response) -> Response:
    if use_own_ua:
        # We keep a list user agents in order to build a list to use in the capture
        # interface: this is the easiest way to have something up to date.
        # The reason we also get the IP address of the client is because we
        # count the frequency of each user agents and use it to sort them on the
        # capture page, and we want to avoid counting the same user (same IP)
        # multiple times in a day.
        # The cache of IPs is deleted after the UA file is generated once a day.
        # See bin/background_processing.py
        ua = request.headers.get('User-Agent')
        real_ip = src_request_ip(request)
        if ua:
            today = date.today().isoformat()
            lookyloo.redis.zincrby(f'user_agents|{today}', 1, f'{real_ip}|{ua}')
    # Opt out of FLoC
    response.headers.set('Permissions-Policy', 'interest-cohort=()')
    return response


def file_response(func):  # type: ignore[no-untyped-def]
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Response:  # type: ignore[no-untyped-def]
        try:
            return func(*args, **kwargs)
        except NoValidHarFile:
            return send_file(BytesIO(b'The capture is broken and does not contain any HAR files.'),
                             mimetype='test/plain', as_attachment=True, download_name='error.txt')
        except MissingUUID as e:
            return send_file(BytesIO(str(e).encode()),
                             mimetype='test/plain', as_attachment=True, download_name='error.txt')

    return wrapper


# ##### Methods querying the indexes #####

def _get_body_hash_investigator(body_hash: str, /) -> tuple[list[tuple[str, str, datetime, str, str]], list[tuple[str, float]]]:
    '''Returns all the captures related to a hash (sha512), used in the web interface.'''
    total_captures, details = get_indexing(flask_login.current_user).get_body_hash_captures(body_hash, limit=-1)
    captures = []
    for capture_uuid, hostnode_uuid, hostname, _, url in details:
        cache = lookyloo.capture_cache(capture_uuid)
        if not cache:
            continue
        captures.append((cache.uuid, cache.title, cache.timestamp, hostnode_uuid, url))
    domains = get_indexing(flask_login.current_user).get_body_hash_domains(body_hash)
    return captures, domains


def get_body_hash_full(body_hash: str, /) -> tuple[dict[str, list[dict[str, str]]], BytesIO]:
    '''Returns a lot of information about the hash (sha512) and the hits in the instance.
    Also contains the data (base64 encoded)'''
    details = get_indexing(flask_login.current_user).get_body_hash_urls(body_hash)

    # Break immediately if we have the hash of the empty file
    if body_hash == 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e':
        return details, BytesIO()

    # get the body from the first entry in the details list
    for _, entries in details.items():
        if not entries:
            continue
        ct = lookyloo.get_crawled_tree(entries[0]['capture'])
        try:
            urlnode = ct.root_hartree.get_url_node_by_uuid(entries[0]['urlnode'])
        except Exception:
            # Unable to find URLnode in the tree, it probably has been rebuild.
            # TODO throw a log line or something
            # self.logger.warning(f'Unable to find {entries[0]["urlnode"]} in entries[0]["capture"]')
            # lookyloo._captures_index.remove_pickle(<capture UUID>)
            continue

        # From that point, we just try to get the content. Break as soon as we found one.
        if urlnode.body_hash == body_hash:
            # the hash we're looking for is the whole file
            return details, urlnode.body
        else:
            # The hash is an embedded resource
            for _, blobs in urlnode.embedded_ressources.items():
                for h, b in blobs:
                    if h == body_hash:
                        return details, b

    # TODO: Couldn't find the file anywhere. Maybe return a warning in the file?
    return details, BytesIO()


def get_all_body_hashes(capture_uuid: str, /) -> dict[str, dict[str, URLNode | int]]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, URLNode | int]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if node.empty_response or node.body_hash in to_return:
            # If we have the same hash more than once, skip
            continue
        total_captures, details = get_indexing(flask_login.current_user).get_body_hash_captures(node.body_hash, limit=-1)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        to_return[node.body_hash] = {'node': node, 'total_captures': total_captures}
    return to_return


def get_all_hostnames(capture_uuid: str, /) -> dict[str, dict[str, int | list[URLNode]]]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, list[URLNode] | int]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if not node.hostname:
            continue
        captures = get_indexing(flask_login.current_user).get_captures_hostname(node.hostname)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        if node.hostname not in to_return:
            to_return[node.hostname] = {'total_captures': len(captures), 'nodes': []}
        to_return[node.hostname]['nodes'].append(node)  # type: ignore[union-attr]
    return to_return


def get_all_urls(capture_uuid: str, /) -> dict[str, dict[str, int | list[URLNode] | str]]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, list[URLNode] | int | str]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if not node.name:
            continue
        captures = get_indexing(flask_login.current_user).get_captures_url(node.name)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        if node.hostname not in to_return:
            to_return[node.name] = {'total_captures': len(captures), 'nodes': [],
                                    'quoted_url': quote_plus(node.name)}
        to_return[node.name]['nodes'].append(node)  # type: ignore[union-attr]
    return to_return


def get_hostname_investigator(hostname: str) -> list[tuple[str, str, str, datetime]]:
    '''Returns all the captures loading content from that hostname, used in the web interface.'''
    cached_captures = lookyloo.sorted_capture_cache([uuid for uuid in get_indexing(flask_login.current_user).get_captures_hostname(hostname=hostname)])
    return [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_url_investigator(url: str) -> list[tuple[str, str, str, datetime]]:
    '''Returns all the captures loading content from that url, used in the web interface.'''
    cached_captures = lookyloo.sorted_capture_cache([uuid for uuid in get_indexing(flask_login.current_user).get_captures_url(url=url)])
    return [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_cookie_name_investigator(cookie_name: str, /) -> tuple[list[tuple[str, str]], list[tuple[str, float, list[tuple[str, float]]]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    cached_captures = lookyloo.sorted_capture_cache([entry[0] for entry in get_indexing(flask_login.current_user).get_cookies_names_captures(cookie_name)])
    captures = [(cache.uuid, cache.title) for cache in cached_captures]
    domains = [(domain, freq, get_indexing(flask_login.current_user).cookies_names_domains_values(cookie_name, domain))
               for domain, freq in get_indexing(flask_login.current_user).get_cookie_domains(cookie_name)]
    return captures, domains


def get_identifier_investigator(identifier_type: str, identifier: str) -> list[tuple[str, str, str, datetime]]:
    cached_captures = lookyloo.sorted_capture_cache([uuid for uuid in get_indexing(flask_login.current_user).get_captures_identifier(identifier_type=identifier_type, identifier=identifier)])
    return [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_capture_hash_investigator(hash_type: str, h: str) -> list[tuple[str, str, str, datetime]]:
    cached_captures = lookyloo.sorted_capture_cache([uuid for uuid in get_indexing(flask_login.current_user).get_captures_hash_type(hash_type=hash_type, h=h)])
    return [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_favicon_investigator(favicon_sha512: str,
                             /,
                             get_probabilistic: bool=False) -> tuple[list[tuple[str, str, str, datetime]],
                                                                     tuple[str, str, str],
                                                                     dict[str, dict[str, dict[str, tuple[str, str]]]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    cached_captures = lookyloo.sorted_capture_cache([uuid for uuid in get_indexing(flask_login.current_user).get_captures_favicon(favicon_sha512)])
    captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]
    favicon = get_indexing(flask_login.current_user).get_favicon(favicon_sha512)
    if favicon:
        mimetype = from_string(favicon, mime=True)
        b64_favicon = base64.b64encode(favicon).decode()
        mmh3_shodan = lookyloo.compute_mmh3_shodan(favicon)
    else:
        mimetype = ''
        b64_favicon = ''
        mmh3_shodan = ''

    # For now, there is only one probabilistic hash algo for favicons, keeping it simple
    probabilistic_hash_algos = ['mmh3-shodan']
    probabilistic_favicons: dict[str, dict[str, dict[str, tuple[str, str]]]] = {}
    if get_probabilistic:
        for algo in probabilistic_hash_algos:
            probabilistic_favicons[algo] = {}
            for mm3hash in get_indexing(flask_login.current_user).get_probabilistic_hashes_favicon(algo, favicon_sha512):
                probabilistic_favicons[algo][mm3hash] = {}
                for sha512 in get_indexing(flask_login.current_user).get_hashes_favicon_probablistic(algo, mm3hash):
                    if sha512 == favicon_sha512:
                        # Skip entry if it is the same as the favicon we are investigating
                        continue
                    favicon = get_indexing(flask_login.current_user).get_favicon(sha512)
                    if favicon:
                        mimetype = from_string(favicon, mime=True)
                        b64_favicon = base64.b64encode(favicon).decode()
                        probabilistic_favicons[algo][mm3hash][sha512] = (mimetype, b64_favicon)
                if not probabilistic_favicons[algo][mm3hash]:
                    # remove entry if it has no favicon
                    probabilistic_favicons[algo].pop(mm3hash)
            if not probabilistic_favicons[algo]:
                # remove entry if it has no hash
                probabilistic_favicons.pop(algo)
    return captures, (mimetype, b64_favicon, mmh3_shodan), probabilistic_favicons


def get_hhh_investigator(hhh: str, /) -> tuple[list[tuple[str, str, str, str]], list[tuple[str, str]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    all_captures = dict(get_indexing(flask_login.current_user).get_http_headers_hashes_captures(hhh))
    if cached_captures := lookyloo.sorted_capture_cache([entry for entry in all_captures]):
        captures = []
        for cache in cached_captures:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(cache.uuid, all_captures[cache.uuid])
            except Exception:
                # NOTE: print a logline
                # logger.warning(f'Cache for {cache.uuid} needs a rebuild: {e}.')
                lookyloo._captures_index.remove_pickle(cache.uuid)
                continue
            captures.append((cache.uuid, urlnode.hostnode_uuid, urlnode.name, cache.title))
        # get the headers and format them as they were in the response
        urlnode = lookyloo.get_urlnode_from_tree(cached_captures[0].uuid, all_captures[cached_captures[0].uuid])
        headers = [(header["name"], header["value"]) for header in urlnode.response['headers']]
        return captures, headers
    return [], []


def hash_lookup(blob_hash: str, url: str, capture_uuid: str) -> tuple[int, dict[str, list[tuple[str, str, str, str, str]]]]:
    '''Search all the captures a specific hash was seen.
    If a URL is given, it splits the results if the hash is seen on the same URL or an other one.
    Capture UUID avoids duplicates on the same capture'''
    captures_list: dict[str, list[tuple[str, str, str, str, str]]] = {'same_url': [], 'different_url': []}
    total_captures, details = get_indexing(flask_login.current_user).get_body_hash_captures(blob_hash, url, filter_capture_uuid=capture_uuid, limit=-1,
                                                                                            prefered_uuids=set(lookyloo._captures_index.keys()))
    for h_capture_uuid, url_uuid, url_hostname, same_url, url in details:
        cache = lookyloo.capture_cache(h_capture_uuid)
        if cache and hasattr(cache, 'title'):
            if same_url:
                captures_list['same_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
            else:
                captures_list['different_url'].append((h_capture_uuid, url_uuid, cache.title, cache.timestamp.isoformat(), url_hostname))
    # Sort by timestamp by default
    captures_list['same_url'].sort(key=lambda y: y[3])
    captures_list['different_url'].sort(key=lambda y: y[3])
    return total_captures, captures_list


def get_hostnode_investigator(capture_uuid: str, /, node_uuid: str) -> tuple[HostNode, list[dict[str, Any]]]:
    '''Gather all the informations needed to display the Hostnode investigator popup.'''

    def normalize_known_content(h: str, /, known_content: dict[str, Any], url: URLNode) -> tuple[str | list[Any] | None, tuple[bool, Any] | None]:
        ''' There are a few different sources to figure out known vs. legitimate content,
        this method normalize it for the web interface.'''
        known: str | list[Any] | None = None
        legitimate: tuple[bool, Any] | None = None
        if h not in known_content:
            return known, legitimate

        if known_content[h]['type'] in ['generic', 'sanejs']:
            known = known_content[h]['details']
        elif known_content[h]['type'] == 'legitimate_on_domain':
            legit = False
            if url.hostname in known_content[h]['details']:
                legit = True
            legitimate = (legit, known_content[h]['details'])
        elif known_content[h]['type'] == 'malicious':
            legitimate = (False, known_content[h]['details'])

        return known, legitimate

    ct = lookyloo.get_crawled_tree(capture_uuid)
    hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)

    known_content = lookyloo.context.find_known_content(hostnode)
    lookyloo.uwhois.query_whois_hostnode(hostnode)

    urls: list[dict[str, Any]] = []
    for url in hostnode.urls:
        # For the popup, we need:
        # * https vs http
        # * everything after the domain
        # * the full URL
        to_append: dict[str, Any] = {
            'encrypted': url.name.startswith('https'),
            'url_path': url.name.split('/', 3)[-1],
            'url_object': url,
        }

        if not url.empty_response:
            # Index lookup
            # %%% Full body %%%
            freq = get_indexing(flask_login.current_user).body_hash_fequency(url.body_hash)
            to_append['body_hash_details'] = freq
            if freq and 'hash_freq' in freq and freq['hash_freq'] and freq['hash_freq'] > 1:
                to_append['body_hash_details']['other_captures'] = hash_lookup(url.body_hash, url.name, capture_uuid)

            # %%% Embedded ressources %%%
            if hasattr(url, 'embedded_ressources') and url.embedded_ressources:
                to_append['embedded_ressources'] = {}
                for mimetype, blobs in url.embedded_ressources.items():
                    for h, blob in blobs:
                        if h in to_append['embedded_ressources']:
                            # Skip duplicates
                            continue
                        freq_embedded = get_indexing(flask_login.current_user).body_hash_fequency(h)
                        to_append['embedded_ressources'][h] = freq_embedded
                        to_append['embedded_ressources'][h]['body_size'] = blob.getbuffer().nbytes
                        to_append['embedded_ressources'][h]['type'] = mimetype
                        if freq_embedded['hash_freq'] > 1:
                            to_append['embedded_ressources'][h]['other_captures'] = hash_lookup(h, url.name, capture_uuid)
                for h in to_append['embedded_ressources'].keys():
                    known, legitimate = normalize_known_content(h, known_content, url)
                    if known:
                        to_append['embedded_ressources'][h]['known_content'] = known
                    elif legitimate:
                        to_append['embedded_ressources'][h]['legitimacy'] = legitimate

            known, legitimate = normalize_known_content(url.body_hash, known_content, url)
            if known:
                to_append['known_content'] = known
            elif legitimate:
                to_append['legitimacy'] = legitimate

        # Optional: Cookies sent to server in request -> map to nodes who set the cookie in response
        if hasattr(url, 'cookies_sent'):
            to_display_sent: dict[str, set[Iterable[str | None]]] = defaultdict(set)
            for cookie, contexts in url.cookies_sent.items():
                if not contexts:
                    # Locally created?
                    to_display_sent[cookie].add(('Unknown origin', ))
                    continue
                for context in contexts:
                    to_display_sent[cookie].add((context['setter'].hostname, context['setter'].hostnode_uuid))
            to_append['cookies_sent'] = to_display_sent

        # Optional: Cookies received from server in response -> map to nodes who send the cookie in request
        if hasattr(url, 'cookies_received'):
            to_display_received: dict[str, dict[str, set[Iterable[str | None]]]] = {'3rd_party': defaultdict(set), 'sent': defaultdict(set), 'not_sent': defaultdict(set)}
            for domain, c_received, is_3rd_party in url.cookies_received:
                if c_received not in ct.root_hartree.cookies_sent:
                    # This cookie is never sent.
                    if is_3rd_party:
                        to_display_received['3rd_party'][c_received].add((domain, ))
                    else:
                        to_display_received['not_sent'][c_received].add((domain, ))
                    continue

                for url_node in ct.root_hartree.cookies_sent[c_received]:
                    if is_3rd_party:
                        to_display_received['3rd_party'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
                    else:
                        to_display_received['sent'][c_received].add((url_node.hostname, url_node.hostnode_uuid))
            to_append['cookies_received'] = to_display_received

        urls.append(to_append)
    return hostnode, urls


# ##### Hostnode level methods #####

@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[misc]
def hashes_hostnode(tree_uuid: str, node_uuid: str) -> Response:
    hashes = lookyloo.get_hashes(tree_uuid, hostnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name=f'hashes.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/text', methods=['GET'])
@file_response  # type: ignore[misc]
def urls_hostnode(tree_uuid: str, node_uuid: str) -> Response:
    hostnode = lookyloo.get_hostnode_from_tree(tree_uuid, node_uuid)
    return send_file(BytesIO('\n'.join(url.name for url in hostnode.urls).encode()),
                     mimetype='test/plain', as_attachment=True, download_name=f'urls.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>', methods=['GET'])
def hostnode_popup(tree_uuid: str, node_uuid: str) -> str | WerkzeugResponse | Response:
    try:
        hostnode, urls = get_hostnode_investigator(tree_uuid, node_uuid)
    except IndexError:
        return render_template('error.html', error_message='Sorry, this one is on us. The tree was rebuild, please reload the tree and try again.')

    return render_template('hostname_popup.html',
                           tree_uuid=tree_uuid,
                           hostnode_uuid=node_uuid,
                           hostnode=hostnode,
                           urls=urls,
                           has_pandora=lookyloo.pandora.available,
                           enable_context_by_users=enable_context_by_users,
                           uwhois_available=lookyloo.uwhois.available)


# ##### Tree level Methods #####

@app.route('/tree/<string:tree_uuid>/trigger_modules', methods=['GET'])
def trigger_modules(tree_uuid: str) -> WerkzeugResponse | str | Response:
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    auto_trigger = True if (request.args.get('auto_trigger') and request.args.get('auto_trigger') == 'True') else False
    lookyloo.trigger_modules(tree_uuid, force=force, auto_trigger=auto_trigger)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/historical_lookups', methods=['GET'])
def historical_lookups(tree_uuid: str) -> str | WerkzeugResponse | Response:
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    data = lookyloo.get_historical_lookups(tree_uuid, force)
    return render_template('historical_lookups.html', tree_uuid=tree_uuid,
                           riskiq=data.get('riskiq'),
                           circl_pdns=data.get('circl_pdns'))


@app.route('/tree/<string:tree_uuid>/categories_capture/', defaults={'query': ''})
@app.route('/tree/<string:tree_uuid>/categories_capture/<string:query>', methods=['GET'])
def categories_capture(tree_uuid: str, query: str) -> str | WerkzeugResponse | Response:
    if not enable_categorization:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    current_categories = lookyloo.categories_capture(tree_uuid)
    matching_categories = None
    if query:
        matching_categories = {}
        t = get_taxonomies()
        entries = t.search(query)
        if entries:
            matching_categories = {e: t.revert_machinetag(e) for e in entries}
    return render_template('categories_capture.html', tree_uuid=tree_uuid,
                           current_categories=current_categories,
                           matching_categories=matching_categories)


@app.route('/tree/<string:tree_uuid>/uncategorize/', defaults={'category': ''})
@app.route('/tree/<string:tree_uuid>/uncategorize/<string:category>', methods=['GET'])
def uncategorize_capture(tree_uuid: str, category: str) -> str | WerkzeugResponse | Response:
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.uncategorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully added to {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/categorize/', defaults={'category': ''})
@app.route('/tree/<string:tree_uuid>/categorize/<string:category>', methods=['GET'])
def categorize_capture(tree_uuid: str, category: str) -> str | WerkzeugResponse | Response:
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.categorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully removed from {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str) -> str:
    stats = lookyloo.get_statistics(tree_uuid)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


@app.route('/tree/<string:tree_uuid>/misp_lookup', methods=['GET'])
@flask_login.login_required  # type: ignore[misc]
def web_misp_lookup_view(tree_uuid: str) -> str | WerkzeugResponse | Response:
    if not lookyloo.misps.available:
        flash('There are no MISP instances available.', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    misps_occurrences = {}
    for instance_name in lookyloo.misps.keys():
        if occurrences := lookyloo.get_misp_occurrences(tree_uuid, instance_name=instance_name):
            misps_occurrences[instance_name] = occurrences
    return render_template('misp_lookup.html', uuid=tree_uuid,
                           current_misp=lookyloo.misps.default_instance,
                           misps_occurrences=misps_occurrences)


@app.route('/tree/<string:tree_uuid>/misp_push', methods=['GET', 'POST'])
@flask_login.login_required  # type: ignore[misc]
def web_misp_push_view(tree_uuid: str) -> str | WerkzeugResponse | Response | None:
    if not lookyloo.misps.available:
        flash('There are no MISP instances available.', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    event = lookyloo.misp_export(tree_uuid)
    if isinstance(event, dict):
        flash(f'Unable to generate the MISP export: {event}', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    if request.method == 'GET':
        # Initialize settings that will be displayed on the template
        misp_instances_settings = {}
        for name, instance in lookyloo.misps.items():
            # the 1st attribute in the event is the link to lookyloo
            misp_instances_settings[name] = {
                'default_tags': instance.default_tags,
                'fav_tags': [tag.name for tag in instance.get_fav_tags()],
                'auto_publish': instance.auto_publish
            }
            if existing_misp_url := instance.get_existing_event_url(event[-1].attributes[0].value):
                misp_instances_settings[name]['existing_event'] = existing_misp_url

        cache = lookyloo.capture_cache(tree_uuid)
        return render_template('misp_push_view.html',
                               current_misp=lookyloo.misps.default_instance,
                               tree_uuid=tree_uuid,
                               event=event[0],
                               misp_instances_settings=misp_instances_settings,
                               has_parent=True if cache and cache.parent else False)

    elif request.method == 'POST':
        # event is a MISPEvent at this point
        misp_instance_name = request.form.get('misp_instance_name')
        if not misp_instance_name or misp_instance_name not in lookyloo.misps:
            flash(f'MISP instance {misp_instance_name} is unknown.', 'error')
            return redirect(url_for('tree', tree_uuid=tree_uuid))
        misp = lookyloo.misps[misp_instance_name]
        if not misp.enable_push:
            flash('Push not enabled in MISP module.', 'error')
            return redirect(url_for('tree', tree_uuid=tree_uuid))
        # Submit the event
        tags = request.form.getlist('tags')
        error = False
        events: list[MISPEvent] = []
        with_parents = request.form.get('with_parents')
        if with_parents:
            exports = lookyloo.misp_export(tree_uuid, True)
            if isinstance(exports, dict):
                flash(f'Unable to create event: {exports}', 'error')
                error = True
            else:
                events = exports
        else:
            events = event

        if error:
            return redirect(url_for('tree', tree_uuid=tree_uuid))

        for e in events:
            for tag in tags:
                e.add_tag(tag)

        # Change the event info field of the last event in the chain
        events[-1].info = request.form.get('event_info')

        try:
            new_events = misp.push(events, True if request.form.get('force_push') else False,
                                   True if request.form.get('auto_publish') else False)
        except MISPServerError:
            flash(f'MISP returned an error, the event(s) might still have been created on {misp.client.root_url}', 'error')
        else:
            if isinstance(new_events, dict):
                flash(f'Unable to create event(s): {new_events}', 'error')
            else:
                for e in new_events:
                    flash(f'MISP event {e.id} created on {misp.client.root_url}', 'success')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    return None


@app.route('/tree/<string:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid: str) -> str | WerkzeugResponse | Response:
    modules_responses = lookyloo.get_modules_responses(tree_uuid)
    if not modules_responses:
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    vt_short_result: dict[str, dict[str, Any]] = {}
    if 'vt' in modules_responses:
        # VirusTotal cleanup
        vt = modules_responses.pop('vt')
        # Get malicious entries
        for url, full_report in vt.items():
            if not full_report:
                continue
            vt_short_result[url] = {
                'permaurl': f'https://www.virustotal.com/gui/url/{full_report["id"]}/detection',
                'malicious': []
            }
            for vendor, result in full_report['attributes']['last_analysis_results'].items():
                if result['category'] == 'malicious':
                    vt_short_result[url]['malicious'].append((vendor, result['result']))

    pi_short_result: dict[str, str] = {}
    if 'pi' in modules_responses:
        pi = modules_responses.pop('pi')
        for url, full_report in pi.items():
            if not full_report:
                continue
            pi_short_result[url] = full_report['results'][0]['tag_label']

    phishtank_short_result: dict[str, dict[str, Any]] = {'urls': {}, 'ips_hits': {}}
    if 'phishtank' in modules_responses:
        pt = modules_responses.pop('phishtank')
        for url, full_report in pt['urls'].items():
            if not full_report:
                continue
            phishtank_short_result['urls'][url] = full_report['phish_detail_url']

        for ip, entries in pt['ips_hits'].items():
            if not entries:
                continue
            phishtank_short_result['ips_hits'] = {ip: []}
            for full_report in entries:
                phishtank_short_result['ips_hits'][ip].append((
                    full_report['url'],
                    full_report['phish_detail_url']))

    urlhaus_short_result: dict[str, list[Any]] = {'urls': []}
    if 'urlhaus' in modules_responses:
        # TODO: make a short result
        uh = modules_responses.pop('urlhaus')
        for url, results in uh['urls'].items():
            if results:
                urlhaus_short_result['urls'].append(results)

    urlscan_to_display: dict[str, Any] = {}
    if 'urlscan' in modules_responses and modules_responses.get('urlscan'):
        urlscan = modules_responses.pop('urlscan')
        if 'error' in urlscan['submission']:
            if 'description' in urlscan['submission']['error']:
                urlscan_to_display = {'error_message': urlscan['submission']['error']['description']}
            else:
                urlscan_to_display = {'error_message': urlscan['submission']['error']}
        else:
            urlscan_to_display = {'permaurl': '', 'malicious': False, 'tags': []}
            if urlscan['submission'] and urlscan['submission'].get('result'):
                urlscan_to_display['permaurl'] = urlscan['submission']['result']
                if urlscan['result']:
                    # We have a result available, get the verdicts
                    if (urlscan['result'].get('verdicts')
                            and urlscan['result']['verdicts'].get('overall')):
                        if urlscan['result']['verdicts']['overall'].get('malicious') is not None:
                            urlscan_to_display['malicious'] = urlscan['result']['verdicts']['overall']['malicious']
                        if urlscan['result']['verdicts']['overall'].get('tags'):
                            urlscan_to_display['tags'] = urlscan['result']['verdicts']['overall']['tags']
            else:
                # unable to run the query, probably an invalid key
                pass
    return render_template('modules.html', uuid=tree_uuid, vt=vt_short_result,
                           pi=pi_short_result, urlscan=urlscan_to_display,
                           phishtank=phishtank_short_result,
                           urlhaus=urlhaus_short_result)


@app.route('/tree/<string:tree_uuid>/redirects', methods=['GET'])
@file_response  # type: ignore[misc]
def redirects(tree_uuid: str) -> Response:
    cache = lookyloo.capture_cache(tree_uuid)
    if not cache or not hasattr(cache, 'redirects'):
        return Response('Not available.', mimetype='text/text')
    if not cache.redirects:
        return Response('No redirects.', mimetype='text/text')
    if cache.url == cache.redirects[0]:
        to_return = BytesIO('\n'.join(cache.redirects).encode())
    else:
        to_return = BytesIO('\n'.join([cache.url] + cache.redirects).encode())
    return send_file(to_return, mimetype='text/text',
                     as_attachment=True, download_name='redirects.txt')


@app.route('/tree/<string:tree_uuid>/image', methods=['GET'])
@file_response  # type: ignore[misc]
def image(tree_uuid: str) -> Response:
    max_width = request.args.get('width')
    if max_width and max_width.isdigit():
        to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, width=int(max_width))
    else:
        to_return = lookyloo.get_screenshot(tree_uuid)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, download_name='image.png')


@app.route('/tree/<string:tree_uuid>/data', methods=['GET'])
@file_response  # type: ignore[misc]
def data(tree_uuid: str) -> Response:
    filename, data = lookyloo.get_data(tree_uuid)
    if len(filename) == 0:
        return Response('No files.', mimetype='text/text')

    if filetype.guess_mime(data.getvalue()) is None:
        mime = 'application/octet-stream'
    else:
        mime = filetype.guess_mime(data.getvalue())
    return send_file(data, mimetype=mime,
                     as_attachment=True, download_name=filename)


@app.route('/tree/<string:tree_uuid>/thumbnail/', defaults={'width': 64}, methods=['GET'])
@app.route('/tree/<string:tree_uuid>/thumbnail/<int:width>', methods=['GET'])
@file_response  # type: ignore[misc]
def thumbnail(tree_uuid: str, width: int) -> Response:
    to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=False, width=width)
    return send_file(to_return, mimetype='image/png')


@app.route('/tree/<string:tree_uuid>/html', methods=['GET'])
@file_response  # type: ignore[misc]
def html(tree_uuid: str) -> Response:
    to_return = lookyloo.get_html(tree_uuid)
    return send_file(to_return, mimetype='text/html',
                     as_attachment=True, download_name='page.html')


@app.route('/tree/<string:tree_uuid>/cookies', methods=['GET'])
@file_response  # type: ignore[misc]
def cookies(tree_uuid: str) -> Response:
    to_return = lookyloo.get_cookies(tree_uuid)
    return send_file(to_return, mimetype='application/json',
                     as_attachment=True, download_name='cookies.json')


@app.route('/tree/<string:tree_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[misc]
def hashes_tree(tree_uuid: str) -> Response:
    hashes = lookyloo.get_hashes(tree_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name='hashes.txt')


@app.route('/tree/<string:tree_uuid>/export', methods=['GET'])
@file_response  # type: ignore[misc]
def export(tree_uuid: str) -> Response:
    to_return = lookyloo.get_capture(tree_uuid)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, download_name='capture.zip')


@app.route('/tree/<string:tree_uuid>/urls_rendered_page', methods=['GET'])
def urls_rendered_page(tree_uuid: str) -> WerkzeugResponse | str | Response:
    try:
        urls = lookyloo.get_urls_rendered_page(tree_uuid)
        return render_template('urls_rendered.html', base_tree_uuid=tree_uuid, urls=urls)
    except Exception:
        flash('Unable to find the rendered node in this capture, cannot get the URLs.', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/hashlookup', methods=['GET'])
def hashlookup(tree_uuid: str) -> str | WerkzeugResponse | Response:
    merged, total_ressources = lookyloo.merge_hashlookup_tree(tree_uuid)
    # We only want unique URLs for the template
    for sha1, entries in merged.items():
        entries['nodes'] = {node.name for node in entries['nodes']}
    return render_template('hashlookup.html', base_tree_uuid=tree_uuid, merged=merged, total_ressources=total_ressources)


@app.route('/bulk_captures/<string:base_tree_uuid>', methods=['POST'])
def bulk_captures(base_tree_uuid: str) -> WerkzeugResponse | str | Response:
    if flask_login.current_user.is_authenticated:
        user = flask_login.current_user.get_id()
    else:
        user = src_request_ip(request)
    selected_urls = request.form.getlist('url')
    urls = lookyloo.get_urls_rendered_page(base_tree_uuid)
    cache = lookyloo.capture_cache(base_tree_uuid)
    if not cache:
        flash('Unable to find capture {base_tree_uuid} in cache.', 'error')
        return redirect(url_for('tree', tree_uuid=base_tree_uuid))
    cookies = load_cookies(lookyloo.get_cookies(base_tree_uuid))
    bulk_captures = []
    for url in [urls[int(selected_id) - 1] for selected_id in selected_urls]:
        capture: CaptureSettings = {
            'url': url,
            'cookies': cookies,
            'referer': cache.redirects[-1] if cache.redirects else cache.url,
            'user_agent': cache.user_agent,
            'parent': base_tree_uuid,
            'listing': False if cache and cache.no_index else True
        }
        new_capture_uuid = lookyloo.enqueue_capture(capture, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
        bulk_captures.append((new_capture_uuid, url))

    return render_template('bulk_captures.html', uuid=base_tree_uuid, bulk_captures=bulk_captures)


@app.route('/tree/<string:tree_uuid>/hide', methods=['GET'])
@flask_login.login_required  # type: ignore[misc]
def hide_capture(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.hide_capture(tree_uuid)
    flash('Successfully hidden.', 'success')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/remove', methods=['GET'])
@flask_login.login_required  # type: ignore[misc]
def remove_capture(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.remove_capture(tree_uuid)
    flash(f'{tree_uuid} successfully removed.', 'success')
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/rebuild')
@flask_login.login_required  # type: ignore[misc]
def rebuild_tree(tree_uuid: str) -> WerkzeugResponse:
    try:
        lookyloo.remove_pickle(tree_uuid)
        flash('Successfully rebuilt.', 'success')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    except Exception:
        return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/cache', methods=['GET'])
def cache_tree(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.capture_cache(tree_uuid)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/monitor', methods=['POST', 'GET'])
def monitor(tree_uuid: str) -> WerkzeugResponse:
    if not lookyloo.monitoring_enabled:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    if request.form.get('name') or not request.form.get('confirm'):
        # got a bot.
        logging.info(f'{src_request_ip(request)} is a bot - {request.headers.get("User-Agent")}.')
        return redirect('https://www.youtube.com/watch?v=iwGFalTRHDA')

    collection: str = request.form['collection'] if request.form.get('collection') else ''
    notification_email: str = request.form['notification'] if request.form.get('notification') else ''
    frequency: str = request.form['frequency'] if request.form.get('frequency') else 'daily'
    expire_at: float | None = datetime.fromisoformat(request.form['expire_at']).timestamp() if request.form.get('expire_at') else None
    cache = lookyloo.capture_cache(tree_uuid)
    if cache:
        monitoring_uuid = lookyloo.monitoring.monitor({'url': cache.url, 'user_agent': cache.user_agent, 'listing': False},
                                                      frequency=frequency, collection=collection, expire_at=expire_at,
                                                      notification={'email': notification_email})
        flash(f"Sent to monitoring ({monitoring_uuid}).", 'success')
        if collection:
            flash(f"See monitored captures in the same collection here: {lookyloo.monitoring.root_url}/monitored/{collection}.", 'success')
        else:
            flash(f"Comparison available as soon as we have more than one capture: {lookyloo.monitoring.root_url}/changes_tracking/{monitoring_uuid}.", 'success')
    else:
        flash(f"Unable to send to monitoring, uuid {tree_uuid} not found in cache.", 'error')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str) -> WerkzeugResponse:
    if not enable_mail_notification:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    if request.form.get('name') or not request.form.get('confirm'):
        # got a bot.
        logging.info(f'{src_request_ip(request)} is a bot - {request.headers.get("User-Agent")}.')
        return redirect('https://www.youtube.com/watch?v=iwGFalTRHDA')

    email: str = request.form['email'] if request.form.get('email') else ''
    if '@' not in email:
        # skip clearly incorrect emails
        email = ''
    comment: str = request.form['comment'] if request.form.get('comment') else ''
    lookyloo.send_mail(tree_uuid, email, comment)
    flash("Email notification sent", 'success')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
@app.route('/tree/<string:tree_uuid>/<string:node_uuid>', methods=['GET'])
def tree(tree_uuid: str, node_uuid: str | None=None) -> Response | str | WerkzeugResponse:
    if tree_uuid == 'False':
        flash("Unable to process your request.", 'warning')
        return redirect(url_for('index'))
    try:
        cache = lookyloo.capture_cache(tree_uuid, force_update=True)
        if not cache:
            status = lookyloo.get_capture_status(tree_uuid)
            if status == CaptureStatus.UNKNOWN:
                flash(f'Unable to find this UUID ({tree_uuid}).', 'warning')
                return index_generic()
            elif status == CaptureStatus.QUEUED:
                message = "The capture is queued, but didn't start yet."
            elif status in [CaptureStatus.ONGOING, CaptureStatus.DONE]:
                # If CaptureStatus.DONE, the capture finished between the query to the cache and
                # the request for a status. Give it an extra few seconds.
                message = "The capture is ongoing."
            return render_template('tree_wait.html', message=message, tree_uuid=tree_uuid)
    except LacusUnreachable:
        message = "Unable to connect to the Lacus backend, the capture will start as soon as the administrator wakes up."
        return render_template('tree_wait.html', message=message, tree_uuid=tree_uuid)

    try:
        ct = lookyloo.get_crawled_tree(tree_uuid)
        b64_thumbnail = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=True)
        screenshot_size = lookyloo.get_screenshot(tree_uuid).getbuffer().nbytes
        meta = lookyloo.get_meta(tree_uuid)
        capture_settings = lookyloo.get_capture_settings(tree_uuid)
        # Get a potential favicon, if it exists
        mime_favicon, b64_potential_favicon = lookyloo.get_potential_favicons(tree_uuid, all_favicons=False, for_datauri=True)
        hostnode_to_highlight = None
        if node_uuid:
            try:
                urlnode = ct.root_hartree.get_url_node_by_uuid(node_uuid)
                if urlnode:
                    hostnode_to_highlight = urlnode.hostnode_uuid
            except IndexError:
                # node_uuid is not a urlnode, trying a hostnode
                try:
                    hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
                    if hostnode:
                        hostnode_to_highlight = hostnode.uuid
                except IndexError as e:
                    logging.info(f'Invalid uuid ({e}): {node_uuid}')
                    pass
        if cache.error:
            flash(cache.error, 'warning')

        if lookyloo.monitoring_enabled:
            try:
                monitoring_collections = lookyloo.monitoring.collections()
            except Exception as e:
                monitoring_collections = []
                flash(f'Unable to get existing connections from the monitoring : {e}', 'warning')

        return render_template('tree.html', tree_json=ct.to_json(),
                               info=cache,
                               tree_uuid=tree_uuid, public_domain=lookyloo.public_domain,
                               screenshot_thumbnail=b64_thumbnail, page_title=cache.title if hasattr(cache, 'title') else '',
                               favicon=b64_potential_favicon,
                               mime_favicon=mime_favicon,
                               screenshot_size=screenshot_size,
                               meta=meta, enable_mail_notification=enable_mail_notification,
                               enable_monitoring=lookyloo.monitoring_enabled,
                               ignore_sri=ignore_sri,
                               monitoring_settings=lookyloo.monitoring_settings if lookyloo.monitoring_enabled else None,
                               monitoring_collections=monitoring_collections if lookyloo.monitoring_enabled else [],
                               enable_context_by_users=enable_context_by_users,
                               enable_categorization=enable_categorization,
                               enable_bookmark=enable_bookmark,
                               misp_push=lookyloo.misps.available and lookyloo.misps.default_misp.enable_push,
                               misp_lookup=lookyloo.misps.available and lookyloo.misps.default_misp.enable_lookup,
                               blur_screenshot=blur_screenshot, urlnode_uuid=hostnode_to_highlight,
                               auto_trigger_modules=auto_trigger_modules,
                               confirm_message=confirm_message if confirm_message else 'Tick to confirm.',
                               parent_uuid=cache.parent,
                               has_redirects=True if cache.redirects else False,
                               capture_settings=capture_settings)

    except NoValidHarFile:
        flash(f'Unable to build a tree for {tree_uuid}: {cache.error}.', 'warning')
        return index_generic()
    finally:
        lookyloo.update_tree_cache_info(os.getpid(), 'website')


@app.route('/tree/<string:tree_uuid>/mark_as_legitimate', methods=['POST'])
@flask_login.login_required  # type: ignore[misc]
def mark_as_legitimate(tree_uuid: str) -> Response:
    if request.data:
        legitimate_entries: dict[str, Any] = request.get_json(force=True)
        lookyloo.add_to_legitimate(tree_uuid, **legitimate_entries)
    else:
        lookyloo.add_to_legitimate(tree_uuid)
    return jsonify({'message': 'Legitimate entry added.'})


@app.route('/tree/<string:tree_uuid>/identifiers', methods=['GET'])
def tree_identifiers(tree_uuid: str) -> str:
    to_return: list[tuple[int, str, str]] = []

    for id_type, identifiers in get_indexing(flask_login.current_user).get_identifiers_capture(tree_uuid).items():
        for identifier in identifiers:
            nb_captures = get_indexing(flask_login.current_user).identifier_number_captures(id_type, identifier)
            to_return.append((nb_captures, id_type, identifier))
    return render_template('tree_identifiers.html', tree_uuid=tree_uuid, identifiers=to_return)


@app.route('/tree/<string:tree_uuid>/favicons', methods=['GET'])
def tree_favicons(tree_uuid: str) -> str:
    favicons = []
    favicons_zip = lookyloo.get_potential_favicons(tree_uuid, all_favicons=True, for_datauri=False)
    with ZipFile(favicons_zip, 'r') as myzip:
        for name in myzip.namelist():
            if not name.endswith('.ico'):
                continue
            favicon = myzip.read(name)
            if not favicon:
                continue
            mimetype = from_string(favicon, mime=True)
            favicon_sha512 = hashlib.sha512(favicon).hexdigest()
            frequency = get_indexing(flask_login.current_user).favicon_frequency(favicon_sha512)
            number_captures = get_indexing(flask_login.current_user).favicon_number_captures(favicon_sha512)
            b64_favicon = base64.b64encode(favicon).decode()
            mmh3_shodan = lookyloo.compute_mmh3_shodan(favicon)
            favicons.append((favicon_sha512, frequency, number_captures, mimetype, b64_favicon, mmh3_shodan))
    return render_template('tree_favicons.html', tree_uuid=tree_uuid, favicons=favicons)


@app.route('/tree/<string:tree_uuid>/hashes_types', methods=['GET'])
def tree_capture_hashes_types(tree_uuid: str) -> str:
    to_return: list[tuple[int, str, str]] = []

    for hash_type, h in get_indexing(flask_login.current_user).get_hashes_types_capture(tree_uuid).items():
        nb_captures = get_indexing(flask_login.current_user).hash_number_captures(hash_type, h)
        to_return.append((nb_captures, hash_type, h))
    return render_template('tree_hashes_types.html', tree_uuid=tree_uuid, hashes=to_return)


@app.route('/tree/<string:tree_uuid>/body_hashes', methods=['GET'])
def tree_body_hashes(tree_uuid: str) -> str:
    body_hashes = get_all_body_hashes(tree_uuid)
    return render_template('tree_body_hashes.html', tree_uuid=tree_uuid, body_hashes=body_hashes)


@app.route('/tree/<string:tree_uuid>/hostnames', methods=['GET'])
def tree_hostnames(tree_uuid: str) -> str:
    hostnames = get_all_hostnames(tree_uuid)
    return render_template('tree_hostnames.html', tree_uuid=tree_uuid, hostnames=hostnames)


@app.route('/tree/<string:tree_uuid>/urls', methods=['GET'])
def tree_urls(tree_uuid: str) -> str:
    urls = get_all_urls(tree_uuid)
    return render_template('tree_urls.html', tree_uuid=tree_uuid, urls=urls)


@app.route('/tree/<string:tree_uuid>/pandora', methods=['GET', 'POST'])
def pandora_submit(tree_uuid: str) -> dict[str, Any] | Response:
    node_uuid = None
    if request.method == 'POST':
        input_json = request.get_json(force=True)
        node_uuid = input_json.get('node_uuid')
        h_request = input_json.get('ressource_hash')
    if node_uuid:
        ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_request)
        if ressource:
            filename, content, mimetype = ressource
        elif h_request:
            return {'error': 'Unable to find resource {h_request} in node {node_uuid} of tree {tree_uuid}'}
        else:
            return {'error': 'Unable to find resource in node {node_uuid} of tree {tree_uuid}'}
    else:
        filename, content = lookyloo.get_data(tree_uuid)

    response = lookyloo.pandora.submit_file(content, filename)
    return jsonify(response)


# ##### helpers #####

def index_generic(show_hidden: bool=False, show_error: bool=True, category: str | None=None) -> str:
    """This method is used to generate the index page. It is possible that some of the captures
    do not have their pickle yet.

    We must assume that calling cached.tree will fail, and handle it gracefully.
    """
    titles = []
    cut_time: datetime | None = None
    if time_delta_on_index:
        # We want to filter the captures on the index
        cut_time = (datetime.now() - timedelta(**time_delta_on_index))
        cut_time_with_tz = cut_time.replace(tzinfo=timezone.utc)

    for cached in lookyloo.sorted_capture_cache(index_cut_time=cut_time):
        if cut_time and cached.timestamp < cut_time_with_tz:
            continue

        if category:
            if not cached.categories or category not in cached.categories:
                continue

        if show_hidden:
            # Only display the hidden ones
            if not cached.no_index:
                continue
        elif cached.no_index:
            continue

        if not show_error and cached.error:
            continue

        titles.append((cached.uuid, cached.title, cached.timestamp.isoformat(), cached.url,
                       cached.redirects))
    titles = sorted(titles, key=lambda x: (x[2], x[3]), reverse=True)
    return render_template('index.html', titles=titles, public_domain=lookyloo.public_domain,
                           show_project_page=get_config('generic', 'show_project_page'),
                           version=pkg_version)


def get_index_params(request: Request) -> tuple[bool, str]:
    show_error: bool = True
    category: str = ''
    if hide_captures_with_error:
        show_error = True if (request.args.get('show_error') and request.args.get('show_error') == 'True') else False

    if enable_categorization:
        category = request.args['category'] if request.args.get('category') else ''
    return show_error, category


# ##### Index level methods #####

@app.route('/', methods=['GET'])
def index() -> str:
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    show_error, category = get_index_params(request)
    return index_generic(show_error=show_error)


@app.route('/hidden', methods=['GET'])
@flask_login.login_required  # type: ignore[misc]
def index_hidden() -> str:
    show_error, category = get_index_params(request)
    return index_generic(show_hidden=True, show_error=show_error, category=category)


@app.route('/cookies', methods=['GET'])
def cookies_lookup() -> str:
    cookies_names = [(name, freq, get_indexing(flask_login.current_user).cookies_names_number_domains(name))
                     for name, freq in get_indexing(flask_login.current_user).cookies_names]
    return render_template('cookies.html', cookies_names=cookies_names)


@app.route('/hhhashes', methods=['GET'])
def hhhashes_lookup() -> str:
    hhhashes = [(hhh, freq, get_indexing(flask_login.current_user).http_headers_hashes_number_captures(hhh))
                for hhh, freq in get_indexing(flask_login.current_user).http_headers_hashes]
    return render_template('hhhashes.html', hhhashes=hhhashes)


@app.route('/favicons', methods=['GET'])
def favicons_lookup() -> str:
    favicons = []
    for sha512, freq in get_indexing(flask_login.current_user).favicons:
        favicon = get_indexing(flask_login.current_user).get_favicon(sha512)
        if not favicon:
            continue
        favicon_b64 = base64.b64encode(favicon).decode()
        nb_captures = get_indexing(flask_login.current_user).favicon_number_captures(sha512)
        favicons.append((sha512, freq, nb_captures, favicon_b64))
    return render_template('favicons.html', favicons=favicons)


@app.route('/ressources', methods=['GET'])
def ressources() -> str:
    ressources = []
    for h, freq in get_indexing(flask_login.current_user).ressources:
        domain_freq = get_indexing(flask_login.current_user).ressources_number_domains(h)
        context = lookyloo.context.find_known_content(h)
        capture_uuid, url_uuid, hostnode_uuid = get_indexing(flask_login.current_user).get_hash_uuids(h)
        try:
            ressource = lookyloo.get_ressource(capture_uuid, url_uuid, h)
        except MissingUUID:
            pass
        if ressource:
            ressources.append((h, freq, domain_freq, context.get(h), capture_uuid, url_uuid, hostnode_uuid, ressource[0], ressource[2]))
        else:
            ressources.append((h, freq, domain_freq, context.get(h), capture_uuid, url_uuid, hostnode_uuid, 'unknown', 'unknown'))
    return render_template('ressources.html', ressources=ressources)


@app.route('/categories', methods=['GET'])
def categories() -> str:
    return render_template('categories.html', categories=get_indexing(flask_login.current_user).categories)


@app.route('/rebuild_all')
@flask_login.login_required  # type: ignore[misc]
def rebuild_all() -> WerkzeugResponse:
    lookyloo.rebuild_all()
    return redirect(url_for('index'))


@app.route('/rebuild_cache')
@flask_login.login_required  # type: ignore[misc]
def rebuild_cache() -> WerkzeugResponse:
    lookyloo.rebuild_cache()
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
def search() -> str | Response | WerkzeugResponse:
    if request.form.get('url'):
        quoted_url: str = quote_plus(request.form['url'])
        return redirect(url_for('url_details', url=quoted_url))
    if request.form.get('hostname'):
        return redirect(url_for('hostname_details', hostname=request.form.get('hostname')))
    if request.form.get('ressource'):
        return redirect(url_for('body_hash_details', body_hash=request.form.get('ressource')))
    if request.form.get('cookie'):
        return redirect(url_for('cookies_name_detail', cookie_name=request.form.get('cookie')))
    return render_template('search.html')


def _prepare_capture_template(user_ua: str | None, predefined_url: str | None=None) -> str:
    return render_template('capture.html', user_agents=user_agents.user_agents,
                           default=user_agents.default,
                           personal_ua=user_ua,
                           default_public=get_config('generic', 'default_public'),
                           devices=lookyloo.get_playwright_devices(),
                           predefined_url_to_capture=predefined_url if predefined_url else '',
                           has_global_proxy=True if lookyloo.global_proxy else False)


@app.route('/recapture/<string:tree_uuid>', methods=['GET'])
def recapture(tree_uuid: str) -> str | Response | WerkzeugResponse:
    cache = lookyloo.capture_cache(tree_uuid)
    if cache and hasattr(cache, 'url'):
        return _prepare_capture_template(user_ua=request.headers.get('User-Agent'),
                                         predefined_url=cache.url)
    flash(f'Unable to find the capture {tree_uuid} in the cache.', 'error')
    return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))


@app.route('/ressource_by_hash/<string:sha512>', methods=['GET'])
@file_response  # type: ignore[misc]
def ressource_by_hash(sha512: str) -> Response:
    details, body = get_body_hash_full(sha512)
    return send_file(body, as_attachment=True, download_name='ressource.bin')


# ################## Submit existing capture ##################

@app.route('/submit_capture', methods=['GET', 'POST'])
def submit_capture() -> str | Response | WerkzeugResponse:

    if request.method == 'POST':
        listing = True if request.form.get('listing') else False
        uuid = str(uuid4())  # NOTE: new UUID, because we do not want duplicates
        har: dict[str, Any] | None = None
        html: str | None = None
        last_redirected_url: str | None = None
        screenshot: bytes | None = None
        if 'har_file' in request.files and request.files['har_file']:
            har = json.loads(request.files['har_file'].stream.read())
            last_redirected_url = request.form.get('landing_page')
            if 'screenshot_file' in request.files:
                screenshot = request.files['screenshot_file'].stream.read()
            if 'html_file' in request.files:
                html = request.files['html_file'].stream.read().decode()
            lookyloo.store_capture(uuid, is_public=listing, har=har,
                                   last_redirected_url=last_redirected_url,
                                   png=screenshot, html=html)
            return redirect(url_for('tree', tree_uuid=uuid))
        elif 'full_capture' in request.files and request.files['full_capture']:
            # it *only* accepts a lookyloo export.
            cookies: list[dict[str, str]] | None = None
            has_error = False
            with ZipFile(BytesIO(request.files['full_capture'].stream.read()), 'r') as lookyloo_capture:
                potential_favicons = set()
                for filename in lookyloo_capture.namelist():
                    if filename.endswith('0.har.gz'):
                        # new formal
                        har = json.loads(gzip.decompress(lookyloo_capture.read(filename)))
                    elif filename.endswith('0.har'):
                        # old format
                        har = json.loads(lookyloo_capture.read(filename))
                    elif filename.endswith('0.html'):
                        html = lookyloo_capture.read(filename).decode()
                    elif filename.endswith('0.last_redirect.txt'):
                        last_redirected_url = lookyloo_capture.read(filename).decode()
                    elif filename.endswith('0.png'):
                        screenshot = lookyloo_capture.read(filename)
                    elif filename.endswith('0.cookies.json'):
                        # Not required
                        cookies = json.loads(lookyloo_capture.read(filename))
                    elif filename.endswith('potential_favicons.ico'):
                        # We may have more than one favicon
                        potential_favicons.add(lookyloo_capture.read(filename))
                if not har or not html or not last_redirected_url or not screenshot:
                    has_error = True
                    if not har:
                        flash('Invalid submission: missing HAR file', 'error')
                    if not html:
                        flash('Invalid submission: missing HTML file', 'error')
                    if not last_redirected_url:
                        flash('Invalid submission: missing landing page', 'error')
                    if not screenshot:
                        flash('Invalid submission: missing screenshot', 'error')
            if not has_error:
                lookyloo.store_capture(uuid, is_public=listing, har=har,
                                       last_redirected_url=last_redirected_url,
                                       png=screenshot, html=html, cookies=cookies,
                                       potential_favicons=potential_favicons)
                return redirect(url_for('tree', tree_uuid=uuid))
        else:
            flash('Invalid submission: please submit at least an HAR file.', 'error')

    return render_template('submit_capture.html',
                           default_public=get_config('generic', 'default_public'),
                           public_domain=lookyloo.public_domain)


# #############################################################

@app.route('/capture', methods=['GET', 'POST'])
def capture_web() -> str | Response | WerkzeugResponse:
    if flask_login.current_user.is_authenticated:
        user = flask_login.current_user.get_id()
    else:
        user = src_request_ip(request)

    if request.method == 'POST':
        if not (request.form.get('url') or request.form.get('urls') or 'document' in request.files):
            flash('Invalid submission: please submit at least a URL or a document.', 'error')
            return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))

        capture_query: CaptureSettings = {}
        # check if the post request has the file part
        if 'cookies' in request.files and request.files['cookies'].filename:
            capture_query['cookies'] = load_cookies(request.files['cookies'].stream.read())

        if request.form.get('device_name'):
            capture_query['device_name'] = request.form['device_name']
        elif request.form.get('freetext_ua'):
            capture_query['user_agent'] = request.form['freetext_ua']
        elif request.form.get('personal_ua') and request.headers.get('User-Agent'):
            capture_query['user_agent'] = request.headers['User-Agent']
        else:
            capture_query['user_agent'] = request.form['user_agent']
            capture_query['os'] = request.form['os']
            capture_query['browser'] = request.form['browser']

        capture_query['listing'] = True if request.form.get('listing') else False
        capture_query['allow_tracking'] = True if request.form.get('allow_tracking') else False

        if request.form.get('referer'):
            capture_query['referer'] = request.form['referer']

        if request.form.get('dnt'):
            capture_query['dnt'] = request.form['dnt']

        if request.form.get('headers'):
            capture_query['headers'] = request.form['headers']

        if request.form.get('timezone_id'):
            capture_query['timezone_id'] = request.form['timezone_id']

        if request.form.get('locale'):
            capture_query['locale'] = request.form['locale']

        if request.form.get('geo_longitude') and request.form.get('geo_latitude'):
            capture_query['geolocation'] = {'longitude': float(request.form['geo_longitude']),
                                            'latitude': float(request.form['geo_latitude'])}

        if request.form.get('http_auth_username') and request.form.get('http_auth_password'):
            capture_query['http_credentials'] = {'username': request.form['http_auth_username'],
                                                 'password': request.form['http_auth_password']}

        if request.form.get('color_scheme'):
            capture_query['color_scheme'] = request.form['color_scheme']

        if request.form.get('proxy'):
            parsed_proxy = urlparse(request.form['proxy'])
            if parsed_proxy.scheme and parsed_proxy.hostname and parsed_proxy.port:
                if parsed_proxy.scheme in ['http', 'https', 'socks5', 'socks5h']:
                    if (parsed_proxy.username and parsed_proxy.password) or (not parsed_proxy.username and not parsed_proxy.password):
                        capture_query['proxy'] = request.form['proxy']
                    else:
                        flash('You need to enter a username AND a password for your proxy.', 'error')
                else:
                    flash('Proxy scheme not supported: must be http(s) or socks5.', 'error')
            else:
                flash('Invalid proxy: Check that you entered a scheme, a hostname and a port.', 'error')

        # auto report
        if flask_login.current_user.is_authenticated:
            if request.form.get('auto-report'):
                capture_query['auto_report'] = {
                    'email': request.form.get('email', ""),
                    'comment': request.form.get('comment', ""),
                    'recipient_mail': request.form.get('recipient-mail', "")
                }

        if request.form.get('url'):
            capture_query['url'] = request.form['url']
            perma_uuid = lookyloo.enqueue_capture(capture_query, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
            time.sleep(2)
            return redirect(url_for('tree', tree_uuid=perma_uuid))
        elif request.form.get('urls'):
            # bulk query
            bulk_captures = []
            for url in request.form['urls'].strip().split('\n'):
                if not url:
                    continue
                query = capture_query.copy()
                query['url'] = url
                new_capture_uuid = lookyloo.enqueue_capture(query, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
                bulk_captures.append((new_capture_uuid, url))

            return render_template('bulk_captures.html', bulk_captures=bulk_captures)
        elif 'document' in request.files:
            # File upload
            capture_query['document'] = base64.b64encode(request.files['document'].stream.read()).decode()
            if request.files['document'].filename:
                capture_query['document_name'] = request.files['document'].filename
            else:
                capture_query['document_name'] = 'unknown_name.bin'
            perma_uuid = lookyloo.enqueue_capture(capture_query, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
            time.sleep(2)
            return redirect(url_for('tree', tree_uuid=perma_uuid))
        else:
            flash('Invalid submission: please submit at least a URL or a document.', 'error')
    elif request.method == 'GET' and request.args.get('url'):
        url = unquote_plus(request.args['url']).strip()
        capture_query = {'url': url}
        perma_uuid = lookyloo.enqueue_capture(capture_query, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
        return redirect(url_for('tree', tree_uuid=perma_uuid))

    # render template
    return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))


@app.route('/simple_capture', methods=['GET', 'POST'])
@flask_login.login_required  # type: ignore[misc]
def simple_capture() -> str | Response | WerkzeugResponse:
    user = flask_login.current_user.get_id()
    if request.method == 'POST':
        if not (request.form.get('url') or request.form.get('urls')):
            flash('Invalid submission: please submit at least a URL.', 'error')
            return render_template('simple_capture.html')
        capture_query: CaptureSettings = {}
        if request.form.get('url'):
            capture_query['url'] = request.form['url']
            perma_uuid = lookyloo.enqueue_capture(capture_query, source='web', user=user,
                                                  authenticated=flask_login.current_user.is_authenticated)
            time.sleep(2)
            if perma_uuid:
                flash('Recording is in progress and is reported automatically.', 'success')
            return redirect(url_for('simple_capture'))
        elif request.form.get('urls'):
            for url in request.form['urls'].strip().split('\n'):
                if not url:
                    continue
                query = capture_query.copy()
                query['url'] = url
                new_capture_uuid = lookyloo.enqueue_capture(query, source='web', user=user,
                                                            authenticated=flask_login.current_user.is_authenticated)
                if new_capture_uuid:
                    flash('Recording is in progress and is reported automatically.', 'success')
            return redirect(url_for('simple_capture'))
    # render template
    return render_template('simple_capture.html')


@app.route('/cookies/<string:cookie_name>', methods=['GET'])
def cookies_name_detail(cookie_name: str) -> str:
    captures, domains = get_cookie_name_investigator(cookie_name.strip())
    return render_template('cookie_name.html', cookie_name=cookie_name, domains=domains, captures=captures)


@app.route('/hhhdetails/<string:hhh>', methods=['GET'])
def hhh_detail(hhh: str) -> str:
    captures, headers = get_hhh_investigator(hhh.strip())
    return render_template('hhh_details.html', hhh=hhh, captures=captures, headers=headers)


@app.route('/identifier_details/<string:identifier_type>/<string:identifier>', methods=['GET'])
def identifier_details(identifier_type: str, identifier: str) -> str:
    captures = get_identifier_investigator(identifier_type, identifier)
    return render_template('identifier_details.html', identifier_type=identifier_type,
                           identifier=identifier,
                           captures=captures)


@app.route('/capture_hash_details/<string:hash_type>/<string:h>', methods=['GET'])
def capture_hash_details(hash_type: str, h: str) -> str:
    captures = get_capture_hash_investigator(hash_type, h)
    return render_template('identifier_details.html', hash_type=hash_type,
                           h=h,
                           captures=captures)


@app.route('/favicon_details/<string:favicon_sha512>', methods=['GET'])
@app.route('/favicon_details/<string:favicon_sha512>/<int:get_probabilistic>', methods=['GET'])
def favicon_detail(favicon_sha512: str, get_probabilistic: int=0) -> str:
    _get_prob = bool(get_probabilistic)
    captures, favicon, probabilistic_favicons = get_favicon_investigator(favicon_sha512.strip(), get_probabilistic=_get_prob)
    mimetype, b64_favicon, mmh3_shodan = favicon
    return render_template('favicon_details.html', favicon_sha512=favicon_sha512,
                           captures=captures, mimetype=mimetype, b64_favicon=b64_favicon, mmh3_shodan=mmh3_shodan,
                           probabilistic_favicons=probabilistic_favicons)


@app.route('/body_hashes/<string:body_hash>', methods=['GET'])
def body_hash_details(body_hash: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    captures, domains = _get_body_hash_investigator(body_hash.strip())
    return render_template('body_hash.html', body_hash=body_hash, domains=domains, captures=captures, from_popup=from_popup)


@app.route('/urls/<string:url>', methods=['GET'])
def url_details(url: str) -> str:
    url = unquote_plus(url).strip()
    captures = get_url_investigator(url)
    return render_template('url.html', url=url, captures=captures)


@app.route('/hostnames/<string:hostname>', methods=['GET'])
def hostname_details(hostname: str) -> str:
    captures = get_hostname_investigator(hostname.strip())
    return render_template('hostname.html', hostname=hostname, captures=captures)


@app.route('/stats', methods=['GET'])
def statsfull() -> str:
    stats = lookyloo.get_stats()
    return render_template('stats.html', stats=stats)


@app.route('/whois/<string:query>', methods=['GET'])
@app.route('/whois/<string:query>/<int:email_only>', methods=['GET'])
@file_response  # type: ignore[misc]
def whois(query: str, email_only: int=0) -> Response:
    to_return = lookyloo.uwhois.whois(query, bool(email_only))
    if isinstance(to_return, str):
        return send_file(BytesIO(to_return.encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'whois.{query}.txt')
    return jsonify(to_return)


# ##### Methods related to a specific URLNode #####

@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/request_cookies', methods=['GET'])
@file_response  # type: ignore[misc]
def urlnode_request_cookies(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.request_cookie:
        return None

    return send_file(BytesIO(json.dumps(urlnode.request_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, download_name='request_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/response_cookies', methods=['GET'])
@file_response  # type: ignore[misc]
def urlnode_response_cookies(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.response_cookie:
        return None

    return send_file(BytesIO(json.dumps(urlnode.response_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, download_name='response_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/urls_in_rendered_content', methods=['GET'])
@file_response  # type: ignore[misc]
def urlnode_urls_in_rendered_content(tree_uuid: str, node_uuid: str) -> Response | None:
    # Note: we could simplify it with lookyloo.get_urls_rendered_page, but if at somepoint,
    # we have multiple page rendered on one tree, it will be a problem.
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not hasattr(urlnode, 'rendered_html') or not urlnode.rendered_html:
        return None

    ct = lookyloo.get_crawled_tree(tree_uuid)
    not_loaded_urls = sorted(set(urlnode.urls_in_rendered_page)
                             - set(ct.root_hartree.all_url_requests.keys()))
    to_return = StringIO()
    to_return.writelines([f'{u}\n' for u in not_loaded_urls])
    return send_file(BytesIO(to_return.getvalue().encode()), mimetype='text/plain',
                     as_attachment=True, download_name='urls_in_rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/rendered_content', methods=['GET'])
@file_response  # type: ignore[misc]
def urlnode_rendered_content(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.rendered_html:
        return None
    return send_file(BytesIO(urlnode.rendered_html.getvalue()), mimetype='text/plain',
                     as_attachment=True, download_name='rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/posted_data', methods=['GET'])
@file_response  # type: ignore[misc]
def urlnode_post_request(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.posted_data:
        return None
    posted: str | bytes
    if isinstance(urlnode.posted_data, (dict, list)):
        # JSON blob, pretty print.
        posted = json.dumps(urlnode.posted_data, indent=2)
    else:
        posted = urlnode.posted_data

    if isinstance(posted, str):
        to_return = BytesIO(posted.encode())
        is_blob = False
    else:
        to_return = BytesIO(posted)
        is_blob = True
    to_return.seek(0)

    if is_blob:
        return send_file(to_return, mimetype='application/octet-stream',
                         as_attachment=True, download_name='posted_data.bin')
    else:
        return send_file(to_return, mimetype='text/plain',
                         as_attachment=True, download_name='posted_data.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/ressource', methods=['POST', 'GET'])
@file_response  # type: ignore[misc]
def get_ressource(tree_uuid: str, node_uuid: str) -> Response:
    if request.method == 'POST':
        h_request = request.form.get('ressource_hash')
    else:
        h_request = None
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_request)
    if ressource:
        filename, to_return, mimetype = ressource
        if not mimetype.startswith('image'):
            # Force a .txt extension
            filename += '.txt'
    else:
        to_return = BytesIO(b'Unknown Hash')
        filename = 'file.txt'
        mimetype = 'text/text'
    return send_file(to_return, mimetype=mimetype, as_attachment=True, download_name=filename)


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/ressource_preview', methods=['GET'])
@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/ressource_preview/<string:h_ressource>', methods=['GET'])
@file_response  # type: ignore[misc]
def get_ressource_preview(tree_uuid: str, node_uuid: str, h_ressource: str | None=None) -> Response:
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_ressource)
    if not ressource:
        return Response('No preview available.', mimetype='text/text')
    filename, r, mimetype = ressource
    if mimetype.startswith('image'):
        return send_file(r, mimetype=mimetype,
                         as_attachment=True, download_name=filename)
    return Response('No preview available.', mimetype='text/text')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[misc]
def hashes_urlnode(tree_uuid: str, node_uuid: str) -> Response:
    hashes = lookyloo.get_hashes(tree_uuid, urlnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name='hashes.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/add_context', methods=['POST'])
@flask_login.login_required  # type: ignore[misc]
def add_context(tree_uuid: str, node_uuid: str) -> WerkzeugResponse | None:
    if not enable_context_by_users:
        return redirect(url_for('ressources'))

    context_data = request.form
    ressource_hash: str = context_data['hash_to_contextualize']
    hostnode_uuid: str = context_data['hostnode_uuid']
    callback_str: str = context_data['callback_str']
    legitimate: bool = True if context_data.get('legitimate') else False
    malicious: bool = True if context_data.get('malicious') else False
    details: dict[str, dict[str, Any]] = {'malicious': {}, 'legitimate': {}}
    if malicious:
        malicious_details = {}
        if context_data.get('malicious_type'):
            malicious_details['type'] = context_data['malicious_type']
        if context_data.get('malicious_target'):
            malicious_details['target'] = context_data['malicious_target']
        details['malicious'] = malicious_details
    if legitimate:
        legitimate_details = {}
        if context_data.get('legitimate_domain'):
            legitimate_details['domain'] = context_data['legitimate_domain']
        if context_data.get('legitimate_description'):
            legitimate_details['description'] = context_data['legitimate_description']
        details['legitimate'] = legitimate_details
    lookyloo.add_context(tree_uuid, urlnode_uuid=node_uuid, ressource_hash=ressource_hash,
                         legitimate=legitimate, malicious=malicious, details=details)
    if callback_str == 'hostnode_popup':
        return redirect(url_for('hostnode_popup', tree_uuid=tree_uuid, node_uuid=hostnode_uuid))
    elif callback_str == 'ressources':
        return redirect(url_for('ressources'))
    return None


# Query API
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

CORS(app, resources={r"/submit": {"origins": "*"}})

api = Api(app, title='Lookyloo API',
          description='API to submit captures and query a lookyloo instance.',
          doc='/doc/',
          authorizations=authorizations,
          version=pkg_version)

api.add_namespace(generic_api)
