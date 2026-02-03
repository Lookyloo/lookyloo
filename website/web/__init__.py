#!/usr/bin/env python3

from __future__ import annotations

import base64
import calendar
import functools
import gzip
import hashlib
import http
import ipaddress
import logging
import logging.config
import os
import time

import filetype  # type: ignore[import-untyped]
import orjson

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from difflib import Differ
from importlib.metadata import version
from io import BytesIO, StringIO
from typing import Any, TypedDict
from collections.abc import Sequence
from collections.abc import Iterable
from urllib.parse import unquote_plus, urlparse
from uuid import uuid4
from zipfile import ZipFile
from zoneinfo import ZoneInfo

from har2tree import HostNode, URLNode
import flask_login  # type: ignore[import-untyped]
from flask import (Flask, Response, Request, flash, jsonify, redirect, render_template,
                   request, send_file, url_for, make_response, send_from_directory)
from flask_bootstrap import Bootstrap5  # type: ignore[import-untyped]
from flask_cors import CORS  # type: ignore[import-untyped]
from flask_restx import Api  # type: ignore[import-untyped]
from flask_talisman import Talisman  # type: ignore[import-untyped]
from lacuscore import CaptureStatus, CaptureSettingsError
from markupsafe import Markup, escape
from pylookyloo import PyLookylooError, Lookyloo as PyLookyloo
from puremagic import from_string, PureError
from pymisp import MISPEvent, MISPServerError
from werkzeug.routing import BaseConverter
from werkzeug.security import check_password_hash
from werkzeug.wrappers.response import Response as WerkzeugResponse

from lookyloo import Lookyloo, CaptureSettings, LookylooException
from lookyloo.default import get_config, get_homedir, ConfigError
from lookyloo.exceptions import MissingUUID, NoValidHarFile, LacusUnreachable, TreeNeedsRebuild
from lookyloo.helpers import (UserAgents, load_cookies,
                              load_user_config,
                              get_taxonomies,
                              mimetype_to_generic,
                              )
from pylacus import PyLacus

from zoneinfo import available_timezones

from .genericapi import api as generic_api
from .helpers import (User, build_users_table, get_secret_key,
                      load_user_from_request, src_request_ip, sri_load,
                      get_lookyloo_instance, get_indexing, build_keys_table)
from .proxied import ReverseProxied

logging.config.dictConfig(get_config('logging'))
logger = logging.getLogger('Lookyloo_Website')

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore[method-assign]

app.config['SECRET_KEY'] = get_secret_key()

Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.debug = bool(os.environ.get('DEBUG', False))

try:
    from .custom_csp import csp  # type: ignore[import-untyped]
except ImportError:
    from .default_csp import csp

Talisman(
    app,
    force_https=False,
    content_security_policy_nonce_in=[
        'script-src',
        # Cannot enable that because https://github.com/python-restx/flask-restx/issues/252
        # 'script-src-elem'
    ],
    content_security_policy=csp
)

pkg_version = version('lookyloo')


# Make sure the UUIDs are UUIDs, but keep them as string
class UUIDConverter(BaseConverter):
    regex = (
        r"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
        r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}"
    )


app.url_map.converters['uuid'] = UUIDConverter


class Sha512Converter(BaseConverter):
    regex = (
        r"\w{128}"
    )


app.url_map.converters['sha512'] = Sha512Converter


# Auth stuff
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
build_keys_table()

# User agents manager
user_agents = UserAgents()

if get_config('generic', 'index_is_capture'):
    @app.route('/', methods=['GET'])
    def landing_page() -> WerkzeugResponse | str:
        if request.method == 'HEAD':
            # Just returns ack if the webserver is running
            return 'Ack'
        return redirect(url_for('capture_web'))
else:
    @app.route('/', methods=['GET'])
    def landing_page() -> WerkzeugResponse | str:
        if request.method == 'HEAD':
            # Just returns ack if the webserver is running
            return 'Ack'
        return redirect(url_for('index'))


@login_manager.user_loader  # type: ignore[untyped-decorator]
def user_loader(username: str) -> User | None:
    if username not in build_users_table():
        return None
    user = User()
    user.id = username
    return user


@login_manager.request_loader  # type: ignore[untyped-decorator]
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
        flash(Markup('Logged in as: {}').format(flask_login.current_user.id), 'success')
    else:
        flash(Markup('Unable to login as: {}').format(username), 'error')

    return redirect(url_for('index'))


@app.route('/logout')
@flask_login.login_required  # type: ignore[untyped-decorator]
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


def http_status_description(code: int) -> str:
    if code in http.client.responses:
        return http.client.responses[code]
    return Markup('Invalid code: "{}"').format(code)


def month_name(month: int) -> str:
    return calendar.month_name[month]


def get_sri(directory: str, filename: str) -> str:
    if ignore_sri:
        return ""
    return Markup('integrity="sha512-{}"').format(sri_load()[directory][filename])


# Inspired by: https://stackoverflow.com/questions/59157322/overflow-ellipsis-in-middle-of-a-string
class SafeMiddleEllipsisString():

    def __init__(self, unsafe_string: str | int):
        if isinstance(unsafe_string, int):
            self.unsafe_string = str(unsafe_string)
        else:
            self.unsafe_string = unsafe_string

        self.left, self.right = self.unsafe_string[:len(self.unsafe_string) // 2], self.unsafe_string[len(self.unsafe_string) // 2:]

    def __html_format__(self, format_spec: str) -> Markup:
        if format_spec == "with_title":
            return Markup('<div title="{title}">{ellipsis}</div>').format(title=self.unsafe_string, ellipsis=self.__html__())
        elif format_spec:
            raise ValueError(f"Invalid format spec: {format_spec}")
        return self.__html__()

    def __html__(self) -> Markup:
        return Markup("""
<span class="middleEllipsis">
  <span class="middleEllipsisleft"><div class="middleEllipsiswrap pb-1">{left}</div></span><span class="middleEllipsisright pb-1">&#x202A;{right}</span>
</span>"""
                      ).format(left=self.left, right=self.right)


def shorten_string(s: str | int, with_title: bool=True) -> Markup:
    ss = SafeMiddleEllipsisString(s)
    if with_title:
        return Markup("{s:with_title}").format(s=ss)
    return Markup(ss)


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


all_timezones_set: dict[str, str] = {}
for tzname in sorted(available_timezones()):
    if offset := ZoneInfo(tzname).utcoffset(datetime.now(timezone.utc)):
        all_timezones_set[tzname] = f"UTC{offset.total_seconds() / (60 * 60):+06.2f}"


def get_tz_info() -> tuple[str | None, str, dict[str, str]]:
    now = datetime.now().astimezone()
    local_TZ = now.tzname()
    local_UTC_offset = f'UTC{now.strftime("%z")}'
    return local_TZ, local_UTC_offset, all_timezones_set


def hash_icon_render(tree_uuid: str, urlnode_uuid: str, mimetype: str, h_ressource: str) -> Markup:
    gt = mimetype_to_generic(mimetype)
    if icon_info := get_icon(gt):
        if gt == 'image':
            ressource_preview_url = url_for('get_ressource_preview', tree_uuid=tree_uuid, node_uuid=urlnode_uuid, h_ressource=h_ressource)
            title = Markup('<img class="ressource_preview" src="{}"/>').format(ressource_preview_url)
        else:
            # Just for safety so we *always* have a Markup.
            title = escape(icon_info['tooltip'])

        if gt == 'json':
            title += Markup('<br>Click to view content.')
        else:
            title += Markup('<br>Click to download.')

        render_in_modal = gt in ['json', 'text']

        if render_in_modal:
            url_data_remote = url_for('get_ressource', tree_uuid=tree_uuid, node_uuid=urlnode_uuid, render_in_modal={render_in_modal})
            link_url = Markup('<a href="#JsonRenderModal" data-remote="{}" data-bs-toggle="modal" data-bs-target="#JsonRenderModal" role="button">').format(url_data_remote)
        else:
            url_get_ressource = url_for('get_ressource', tree_uuid=tree_uuid, node_uuid=urlnode_uuid, render_in_modal={render_in_modal})
            link_url = Markup('<a href="{}">').format(url_get_ressource)

        url_img = url_for('static', filename=icon_info['icon'])
        # NOTE: the title contains ", so we absolutely must wrap it in '
        return Markup('{link_url} <img src="{url_img}" alt="{alt_tooltip}" width="21" height="21" data-bs-toggle="tooltip" data-bs-placement="bottom" data-bs-html="true" title=\'{title}\'/></a><br><small>Mimetype: <b>{mimetype}</b></small><br>').format(link_url=link_url, url_img=url_img, alt_tooltip=icon_info['tooltip'], title=title, mimetype=mimetype)
    else:
        return Markup('Unable to render icon')


def details_modal_button(target_modal_id: str, data_remote: str, button_string: Markup, search: str | None=None) -> dict[str, Markup]:
    return {'display': Markup('<a href="{target_modal_id}" data-remote="{data_remote}" data-bs-toggle="modal" data-bs-target="{target_modal_id}" role="button"> {button_string} </a>').format(target_modal_id=target_modal_id, data_remote=data_remote, button_string=button_string),
            'filter': escape(search) if search else button_string}


def load_custom_css(filename: str) -> tuple[str, str] | tuple[()]:
    return load_custom_local_ressource('css', filename)


def load_custom_js(filename: str) -> tuple[str, str] | tuple[()]:
    return load_custom_local_ressource('js', filename)


def load_custom_local_ressource(ressource_type: str, filename: str) -> tuple[str, str] | tuple[()]:
    """Loads a custom file from /static/<ressource_type>/, returns the URL and the SRI"""
    fullpath = get_homedir() / 'website' / 'web' / 'static' / ressource_type / filename
    if not fullpath.exists() or not fullpath.is_file():
        return ()
    # generate the hash for the custom file on the fly
    with fullpath.open('rb') as f:
        sri_hash = f"sha512-{base64.b64encode(hashlib.sha512(f.read()).digest()).decode('utf-8')}"
    url = url_for('static', filename=f'{ressource_type}/{filename}')
    return (url, sri_hash)


app.jinja_env.globals.update(
    {'sizeof_fmt': sizeof_fmt,
     'http_status_description': http_status_description,
     'month_name': month_name,
     'get_sri': get_sri,
     'shorten_string': shorten_string,
     'get_icon': get_icon,
     'generic_type': mimetype_to_generic,
     'hash_icon': hash_icon_render,
     'tz_info': get_tz_info,
     'details_modal_button': details_modal_button,
     'load_custom_css': load_custom_css,
     'load_custom_js': load_custom_js
     }
)


@app.template_filter('b64encode')
def b64enode_filter(blob: str | bytes | BytesIO) -> str:
    to_encode: bytes
    if isinstance(blob, BytesIO):
        to_encode = blob.getvalue()
    elif isinstance(blob, str):
        to_encode = blob.encode()
    else:
        to_encode = blob
    return base64.b64encode(to_encode).decode()


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


@app.errorhandler(CaptureSettingsError)
def handle_pydandic_validation_exception(error: CaptureSettingsError) -> Response | str | WerkzeugResponse:
    '''Return the validation error message and 400 status code'''
    if error.pydantic_validation_errors:
        flash(Markup('Unable to validate capture settings: {}').format(error.pydantic_validation_errors.errors()))
    else:
        flash(escape(error))
    return redirect(url_for('landing_page'))


@app.route('/favicon.ico')
def favicon() -> WerkzeugResponse:
    """Load either the default favicon from static/images/favicons/favicon.ico
    or static/images/favicons/custom-favicon.ico (if it exists)"""

    favicon_path = get_homedir() / 'website' / 'web' / 'static'
    if (favicon_path / 'custom-favicon.ico').exists():
        path = 'custom-favicon.ico'
    else:
        path = 'favicon.ico'
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               path, mimetype='image/vnd.microsoft.icon')


# ##### Methods querying the indexes #####


def _get_body_hash_investigator(body_hash: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures related to a hash (sha512), used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_body_hash_count(body_hash)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_body_hash(body_hash)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_body_hash(body_hash=body_hash, offset=offset, limit=limit), cached_captures_only=False)
    captures = []
    for cache in cached_captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in get_indexing(flask_login.current_user).get_capture_body_hash_nodes(cache.uuid, body_hash):
            try:
                urlnode = lookyloo.get_urlnode_from_tree(cache.uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, nodes_info))
    return total, captures


def get_all_body_hashes(capture_uuid: str, /) -> dict[str, Any]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, int | str | list[tuple[URLNode, bool]]]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if node.empty_response:
            continue
        if node.body_hash not in to_return:
            total_captures = get_indexing(flask_login.current_user).get_captures_body_hash_count(node.body_hash)
            to_return[node.body_hash] = {'total_captures': total_captures, 'mimetype': node.mimetype, 'nodes': []}
        to_return[node.body_hash]['nodes'].append((node, False))  # type: ignore[union-attr]
        # get embedded retources (if any) - need their type too
        if 'embedded_ressources' in node.features:
            for mimetype, blobs in node.embedded_ressources.items():
                for h, blob in blobs:
                    if h not in to_return:
                        total_captures = get_indexing(flask_login.current_user).get_captures_body_hash_count(h)
                        to_return[h] = {'total_captures': total_captures, 'mimetype': mimetype, 'nodes': []}
                    to_return[h]['nodes'].append((node, True))  # type: ignore[union-attr]
    return to_return


def get_hostname_investigator(hostname: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures loading content from that hostname, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_hostname_count(hostname)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_hostname(hostname)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_hostname(hostname=hostname, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_hostname_nodes(cache.uuid, hostname)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_domain_investigator(domain: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures loading content from that domain, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_domain_count(domain)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_domain(domain)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_domain(domain=domain, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_domain_nodes(cache.uuid, domain)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_tld_investigator(tld: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures loading content from that tld, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_tld_count(tld)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_tld(tld)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_tld(tld=tld, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_tld_nodes(cache.uuid, tld)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_ip_investigator(ip: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures loading content from that ip, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_ip_count(ip)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_ip(ip)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_ip(ip=ip, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_ip_nodes(cache.uuid, ip)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_all_ips(capture_uuid: str, /) -> dict[str, Any]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, list[URLNode] | int]] = defaultdict()
    for urlnode in ct.root_hartree.url_tree.traverse():
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        if 'hostname_is_ip' in urlnode.features and urlnode.hostname_is_ip:
            ip = ipaddress.ip_address(urlnode.hostname)
        elif 'ip_address' in urlnode.features:
            ip = urlnode.ip_address

        if not ip:
            continue

        captures_count = get_indexing(flask_login.current_user).get_captures_ip_count(ip.compressed)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        if ip.compressed not in to_return:
            to_return[ip.compressed] = {'total_captures': captures_count, 'hostname': urlnode.hostname, 'nodes': []}
        to_return[ip.compressed]['nodes'].append(urlnode)  # type: ignore[union-attr]
    return to_return


def get_all_hostnames(capture_uuid: str, /) -> dict[str, dict[str, Any]]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, list[URLNode] | int | str]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if not node.hostname:
            continue

        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        if 'hostname_is_ip' in node.features and node.hostname_is_ip:
            ip = ipaddress.ip_address(node.hostname)
        elif 'ip_address' in node.features:
            ip = node.ip_address

        captures_count = get_indexing(flask_login.current_user).get_captures_hostname_count(node.hostname)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        if node.hostname not in to_return:
            to_return[node.hostname] = {'total_captures': captures_count, 'nodes': [], 'ip': ip.compressed if ip else "N/A"}
        to_return[node.hostname]['nodes'].append(node)  # type: ignore[union-attr]
    return to_return


def get_all_urls(capture_uuid: str, /) -> dict[str, dict[str, int | str]]:
    ct = lookyloo.get_crawled_tree(capture_uuid)
    to_return: dict[str, dict[str, int | str]] = defaultdict()
    for node in ct.root_hartree.url_tree.traverse():
        if not node.name:
            continue
        captures_count = get_indexing(flask_login.current_user).get_captures_url_count(node.name)
        # Note for future: mayeb get url, capture title, something better than just the hash to show to the user
        if node.hostname not in to_return:
            to_return[node.name] = {'total_captures': captures_count,  # 'nodes': [],
                                    'quoted_url': base64.urlsafe_b64encode(node.name.encode()).decode()}
        # to_return[node.name]['nodes'].append(node)  # type: ignore[union-attr]
    return to_return


def get_url_investigator(url: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures loading content from that url, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_url_count(url)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_url(url)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_url(url=url, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_url_nodes(cache.uuid, url)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_cookie_name_investigator(cookie_name: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_cookie_name_count(cookie_name)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_cookies_name(cookie_name)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_cookies_name(cookie_name=cookie_name, offset=offset, limit=limit), cached_captures_only=False)
    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_cookie_name_nodes(cache.uuid, cookie_name)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


def get_identifier_investigator(identifier_type: str, identifier: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime]]]:
    '''Returns all the captures related to an identifier, by type'''
    total = get_indexing(flask_login.current_user).get_captures_identifier_count(identifier_type, identifier)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_identifier(identifier_type, identifier)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_identifier(identifier_type=identifier_type, identifier=identifier, offset=offset, limit=limit), cached_captures_only=False)
    return total, [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_capture_hash_investigator(hash_type: str, h: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime]]]:
    '''Returns all the captures related to a capture hash (such has domhash)'''
    total = get_indexing(flask_login.current_user).get_captures_hash_type_count(hash_type, h)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_hash_type(hash_type, h)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_hash_type(hash_type=hash_type, h=h, offset=offset, limit=limit), cached_captures_only=False)
    return total, [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_favicon_investigator(favicon_sha512: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_favicon_count(favicon_sha512)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_favicon(favicon_sha512)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_favicon(favicon_sha512=favicon_sha512, offset=offset, limit=limit), cached_captures_only=False)
    return total, [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp) for cache in cached_captures]


def get_hhh_investigator(hhh: str, offset: int | None=None, limit: int | None=None, search: str | None=None) -> tuple[int, list[tuple[str, str, str, datetime, list[tuple[str, str]]]]]:
    '''Returns all the captures related to a cookie name entry, used in the web interface.'''
    total = get_indexing(flask_login.current_user).get_captures_hhhash_count(hhh)
    if search:
        cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
            [uuid for uuid, _ in get_indexing(flask_login.current_user).scan_captures_hhhash(hhh)], cached_captures_only=False) if capture.search(search)]
    else:
        cached_captures = lookyloo.sorted_capture_cache(
            get_indexing(flask_login.current_user).get_captures_hhhash(hhh, offset=offset, limit=limit), cached_captures_only=False)

    _captures = [(cache.uuid, cache.title, cache.redirects[-1], cache.timestamp, get_indexing(flask_login.current_user).get_capture_hhhash_nodes(cache.uuid, hhh)) for cache in cached_captures]
    captures = []
    for capture_uuid, capture_title, landing_page, capture_ts, nodes in _captures:
        nodes_info: list[tuple[str, str]] = []
        for urlnode_uuid in nodes:
            try:
                urlnode = lookyloo.get_urlnode_from_tree(capture_uuid, urlnode_uuid)
                nodes_info.append((urlnode.name, urlnode_uuid))
            except IndexError:
                continue
        captures.append((capture_uuid, capture_title, landing_page, capture_ts, nodes_info))
    return total, captures


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
            if freq := get_indexing(flask_login.current_user).get_captures_body_hash_count(url.body_hash):
                to_append['body_hash_freq'] = freq

            # %%% Embedded ressources %%%
            if hasattr(url, 'embedded_ressources') and url.embedded_ressources:
                to_append['embedded_ressources'] = {}
                for mimetype, blobs in url.embedded_ressources.items():
                    for h, blob in blobs:
                        if h in to_append['embedded_ressources']:
                            # Skip duplicates
                            continue
                        to_append['embedded_ressources'][h] = {'body_size': blob.getbuffer().nbytes,
                                                               'type': mimetype}
                        if freq := get_indexing(flask_login.current_user).get_captures_body_hash_count(h):
                            to_append['embedded_ressources'][h]['hash_freq'] = freq
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

@app.route('/tree/<uuid:tree_uuid>/host/<uuid:node_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def hashes_hostnode(tree_uuid: str, node_uuid: str) -> Response:
    success, hashes = lookyloo.get_hashes(tree_uuid, hostnode_uuid=node_uuid)
    if success:
        return send_file(BytesIO('\n'.join(hashes).encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'{tree_uuid}_hashes.{node_uuid}.txt')
    return make_response('Unable to get the hashes.', 404)


@app.route('/tree/<uuid:tree_uuid>/host/<uuid:node_uuid>/text', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def urls_hostnode(tree_uuid: str, node_uuid: str) -> Response:
    hostnode = lookyloo.get_hostnode_from_tree(tree_uuid, node_uuid)
    return send_file(BytesIO('\n'.join(url.name for url in hostnode.urls).encode()),
                     mimetype='test/plain', as_attachment=True, download_name=f'{tree_uuid}_urls.{node_uuid}.txt')


@app.route('/tree/<uuid:tree_uuid>/host/<uuid:node_uuid>', methods=['GET'])
def hostnode_popup(tree_uuid: str, node_uuid: str) -> str | WerkzeugResponse | Response:
    try:
        hostnode, urls = get_hostnode_investigator(tree_uuid, node_uuid)
    except IndexError:
        return render_template('error.html', error_message='Sorry, this one is on us. The tree was rebuild, please reload the tree and try again.')

    url_in_address_bar: str | None = None
    diff: str | None = None
    if hostnode.contains_rendered_urlnode:
        url_in_address_bar = '<Unable to load URL from address bar>'
        if u := lookyloo.get_last_url_in_address_bar(tree_uuid):
            url_in_address_bar = unquote_plus(u)
        # we shouldn't havemore than one URL in that node, but it's for sure going to happen, so
        # let's take the first URL node only
        if url_in_address_bar and url_in_address_bar != urls[0]['url_object'].name:
            d = Differ()
            diff = '\n'.join(d.compare([urls[0]['url_object'].name], [url_in_address_bar]))
    return render_template('hostname_popup.html',
                           tree_uuid=tree_uuid,
                           hostnode_uuid=node_uuid,
                           hostnode=hostnode,
                           last_url_in_address_bar=url_in_address_bar,
                           last_url_diff=diff,
                           urls=urls,
                           has_pandora=lookyloo.pandora.available,
                           circl_pdns_available=lookyloo.circl_pdns.available,
                           enable_context_by_users=enable_context_by_users,
                           uwhois_available=lookyloo.uwhois.available)


# ##### Tree level Methods #####

@app.route('/tree/<uuid:tree_uuid>/trigger_modules', methods=['GET'])
def trigger_modules(tree_uuid: str) -> WerkzeugResponse | str | Response:
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    auto_trigger = True if (request.args.get('auto_trigger') and request.args.get('auto_trigger') == 'True') else False
    lookyloo.trigger_modules(tree_uuid, force=force, auto_trigger=auto_trigger, as_admin=flask_login.current_user.is_authenticated)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/historical_lookups', methods=['GET'])
def historical_lookups(tree_uuid: str) -> str | WerkzeugResponse | Response:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    auto_trigger = True if (request.args.get('auto_trigger') and request.args.get('auto_trigger') == 'True') else False
    circl_pdns_queries: set[str | None] = set()
    if cache := lookyloo.capture_cache(tree_uuid):
        triggered = lookyloo.circl_pdns.capture_default_trigger(cache, force=force, auto_trigger=auto_trigger,
                                                                as_admin=flask_login.current_user.is_authenticated)
        if 'error' in triggered:
            flash(Markup('Unable to trigger the historical lookup: {}').format(triggered["error"]), 'error')
        else:
            circl_pdns_queries = {urlparse(url).hostname for url in cache.redirects if urlparse(url).scheme in ['http', 'https'] and urlparse(url).hostname is not None}
    return render_template('historical_lookups.html', tree_uuid=tree_uuid, circl_pdns_queries=circl_pdns_queries, from_popup=from_popup)


@app.route('/tree/<uuid:tree_uuid>/categories_capture', methods=['GET', 'POST'])
def categories_capture(tree_uuid: str) -> str | WerkzeugResponse | Response:
    if not enable_categorization:
        return render_template('categories_view.html', not_enabled=True)
    as_admin = flask_login.current_user.is_authenticated

    if request.method == 'GET':
        taxonomies = get_taxonomies()
        if as_admin:
            can_categorize = True
        else:
            can_categorize = False
        if cache := lookyloo.capture_cache(tree_uuid):
            current_categories = cache.categories
            # only allow categorizing as user if the capture is less than 24h old
            if not as_admin and cache.timestamp >= datetime.now().astimezone() - timedelta(days=1):
                can_categorize = True
        else:
            current_categories = set()
        return render_template('categories_view.html', tree_uuid=tree_uuid,
                               current_categories=current_categories,
                               can_categorize=can_categorize,
                               taxonomy=taxonomies.get('dark-web'))

    # Got a POST
    # If admin, we can remove categories, otherwise, we only add new ones.
    categories = request.form.getlist('categories')
    current, error = lookyloo.categorize_capture(tree_uuid, categories, as_admin=as_admin)
    if current:
        flash(Markup("Current categories {}").format(', '.join(current)), 'success')
    if error:
        flash(Markup("Unable to add categories {}").format(', '.join(error)), 'error')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str) -> str:
    stats = lookyloo.get_statistics(tree_uuid)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


@app.route('/tree/<uuid:tree_uuid>/trusted_timestamp/<string:name>', methods=['GET'])
def trusted_timestamp_tsr(tree_uuid: str, name: str) -> Response:
    if tsr := lookyloo.get_trusted_timestamp(tree_uuid, name):
        return send_file(BytesIO(tsr), as_attachment=True, download_name=f'{tree_uuid}_{name}.tsr')
    return send_file(BytesIO(f'No trusted timestamp for {name}'.encode()), as_attachment=True, download_name='empty.txt')


@app.route('/tree/<uuid:tree_uuid>/all_trusted_timestamp', methods=['GET'])
def all_trusted_timestamp(tree_uuid: str) -> Response:
    bundle = lookyloo.bundle_all_trusted_timestamps(tree_uuid)
    if isinstance(bundle, BytesIO):
        return send_file(bundle, as_attachment=True, download_name=f'{tree_uuid}_all_trusted_timestamps.zip')
    return send_file(BytesIO(f'No trusted timestamp for {tree_uuid}'.encode()), as_attachment=True, download_name='empty.txt')


@app.route('/tree/<uuid:tree_uuid>/download_elements', methods=['GET'])
def download_elements(tree_uuid: str) -> str:
    error: str | None
    tts = lookyloo.check_trusted_timestamps(tree_uuid)
    tt_entries: dict[str, str | datetime]
    if isinstance(tts, dict):
        error = list(tts.values())[0]
        tt_entries = {}
        cert = ''
    else:
        error = None
        tt_entries, cert = tts
    if cache := lookyloo.capture_cache(tree_uuid):
        parent_uuid = True if cache.parent else False
    else:
        parent_uuid = False
    has_downloads, _, _ = lookyloo.get_data(tree_uuid)
    return render_template('download_elements.html', tree_uuid=tree_uuid,
                           tt_entries=tt_entries, parent_uuid=parent_uuid,
                           b64_certificate=cert, error=error,
                           has_downloads=has_downloads)


@app.route('/tree/<uuid:tree_uuid>/get_downloaded_file', methods=['GET'])
def get_downloaded_file(tree_uuid: str) -> Response:
    # NOTE: it can be 0
    index_in_zip = int(request.args['index_in_zip']) if 'index_in_zip' in request.args else None
    success, filename, file = lookyloo.get_data(tree_uuid, index_in_zip=index_in_zip)
    if success:
        return send_file(file, as_attachment=True, download_name=f'{tree_uuid}_{filename}')
    return make_response('Unable to get the downloaded file.', 404)


@app.route('/tree/<uuid:tree_uuid>/downloads', methods=['GET'])
def downloads(tree_uuid: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    success, filename, file = lookyloo.get_data(tree_uuid)
    if not success:
        return render_template('downloads.html', uuid=tree_uuid, files=None)
    if filename and file:
        if filename.strip() == f'{tree_uuid}_multiple_downloads.zip':
            # We have a zipfile containing all the files downloaded during the capture
            with ZipFile(file) as downloaded_files:
                files = []
                for file_info in downloaded_files.infolist():
                    files.append((file_info.filename,))
        else:
            files = [(filename, )]

    # TODO: add other info (like the mimetype)
    return render_template('downloads.html', tree_uuid=tree_uuid, files=files,
                           has_pandora=lookyloo.pandora.available, from_popup=from_popup)


@app.route('/tree/<uuid:tree_uuid>/storage_state', methods=['GET'])
def storage_state(tree_uuid: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    storage = {}
    success, storage_file = lookyloo.get_storage_state(tree_uuid)
    if success and storage_file and storage_file.getvalue():
        storage = orjson.loads(storage_file.getvalue())
        if 'cookies' in storage:
            # insert the frequency
            for cookie in storage['cookies']:
                cookie['frequency'] = get_indexing(flask_login.current_user).get_captures_cookie_name_count(cookie['name'])
    return render_template('storage.html', tree_uuid=tree_uuid, storage=storage, from_popup=from_popup)


@app.route('/tree/<uuid:tree_uuid>/misp_lookup', methods=['GET'])
def web_misp_lookup_view(tree_uuid: str) -> str | WerkzeugResponse | Response:
    if not lookyloo.misps.available:
        flash('There are no MISP instances available.', 'error')
        return render_template('misp_lookup.html', nothing_to_see=True)
    as_admin = flask_login.current_user.is_authenticated
    if not as_admin and not lookyloo.misps.has_public_misp:
        flash('You need to be authenticated to search on MISP.', 'error')
        return render_template('misp_lookup.html', nothing_to_see=True)

    if not as_admin and lookyloo.misps.default_misp.admin_only:
        current_misp = None
    else:
        current_misp = lookyloo.misps.default_instance

    misps_occurrences = {}
    for instance_name, instance in lookyloo.misps.items():
        if instance.admin_only and not as_admin:
            continue
        if not current_misp:
            # Pick the first one we can
            current_misp = instance_name
        if occurrences := lookyloo.get_misp_occurrences(tree_uuid,
                                                        as_admin=as_admin,
                                                        instance_name=instance_name):
            misps_occurrences[instance_name] = occurrences
    return render_template('misp_lookup.html', uuid=tree_uuid,
                           current_misp=current_misp,
                           misps_occurrences=misps_occurrences)


@app.route('/tree/<uuid:tree_uuid>/lookyloo_push', methods=['GET', 'POST'])
def web_lookyloo_push_view(tree_uuid: str) -> str | WerkzeugResponse | Response:
    if request.method == 'GET':
        # Only bots land in this page, avoid log entries.
        flash('Only support POST calls.', 'error')
        return make_response(redirect(url_for('tree', tree_uuid=tree_uuid)), 405)

    if remote_lookyloo_url := request.form.get('remote_lookyloo_url'):
        success, to_push = lookyloo.get_capture(tree_uuid)
        if success:
            pylookyloo = PyLookyloo(remote_lookyloo_url)
            try:
                uuid = pylookyloo.upload_capture(full_capture=to_push, quiet=True)
                flash(Markup('Successfully pushed the capture: <a href="{root_url}/tree/{uuid}" target="_blank">{uuid}</a>.').format(root_url=pylookyloo.root_url, uuid=uuid), 'success')
            except PyLookylooError as e:
                flash(Markup('Error while pushing capture: {}').format(e), 'error')
            except Exception as e:
                flash(Markup('Unable to push capture: {}').format(e), 'error')
        else:
            flash(f'Capture {tree_uuid} does not exist ?!', 'error')
    else:
        flash('Remote Lookyloo URL missing.', 'error')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/misp_push', methods=['GET', 'POST'])
def web_misp_push_view(tree_uuid: str) -> str | WerkzeugResponse | Response:
    if not lookyloo.misps.available:
        flash('There are no MISP instances available.', 'error')
        return render_template('misp_push_view.html', nothing_to_see=True)

    as_admin = flask_login.current_user.is_authenticated
    if not as_admin and not lookyloo.misps.has_public_misp:
        flash('You need to be authenticated to push to MISP.', 'error')
        return render_template('misp_push_view.html', nothing_to_see=True)

    event = lookyloo.misp_export(tree_uuid)
    if isinstance(event, dict):
        flash(Markup('Unable to generate the MISP export: {}').format(event), 'error')
        return render_template('misp_push_view.html', nothing_to_see=True)

    if request.method == 'GET':
        # Initialize settings that will be displayed on the template
        misp_instances_settings = {}
        if not as_admin and lookyloo.misps.default_misp.admin_only:
            current_misp = None
        else:
            current_misp = lookyloo.misps.default_instance
        for name, instance in lookyloo.misps.items():
            if instance.admin_only and not as_admin:
                continue

            if not current_misp:
                # Pick the first one we can
                current_misp = name

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
                               current_misp=current_misp,
                               tree_uuid=tree_uuid,
                               event=event[0],
                               misp_instances_settings=misp_instances_settings,
                               has_parent=True if cache and cache.parent else False)

    else:
        # event is a MISPEvent at this point
        misp_instance_name = request.form.get('misp_instance_name')
        if not misp_instance_name or misp_instance_name not in lookyloo.misps:
            flash(Markup('MISP instance {} is unknown.').format(misp_instance_name), 'error')
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
                flash(Markup('Unable to create event: {}').format(exports), 'error')
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
        events[-1].info = request.form.get('event_info', 'Lookyloo Event')

        try:
            new_events = misp.push(events, as_admin=as_admin,
                                   allow_duplicates=True if request.form.get('force_push') else False,
                                   auto_publish=True if request.form.get('auto_publish') else False,
                                   )
        except MISPServerError:
            flash(Markup('MISP returned an error, the event(s) might still have been created on {}').format(misp.client.root_url), 'error')
        else:
            if isinstance(new_events, dict):
                flash(Markup('Unable to create event(s): {}').format(new_events), 'error')
            else:
                for e in new_events:
                    flash(Markup('MISP event <a href="{root_url}/events/view/{eid}" target="_blank">{eid}</a> created on {root_url}.').format(root_url=misp.client.root_url, eid=e.id), 'success')
        return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid: str) -> str | WerkzeugResponse | Response:
    modules_responses = lookyloo.get_modules_responses(tree_uuid)
    if not modules_responses:
        return render_template('modules.html', nothing_found=True)

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
            if results and 'url' in results:
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


@app.route('/tree/<uuid:tree_uuid>/redirects', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
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
                     as_attachment=True, download_name=f'{tree_uuid}_redirects.txt')


@app.route('/tree/<uuid:tree_uuid>/image', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def image(tree_uuid: str) -> Response:
    max_width = request.args.get('width')
    if max_width and max_width.isdigit():
        to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, width=int(max_width))
    else:
        success, to_return = lookyloo.get_screenshot(tree_uuid)
        if not success:
            error_img = get_homedir() / 'website' / 'web' / 'static' / 'error_screenshot.png'
            with open(error_img, 'rb') as f:
                to_return = BytesIO(f.read())
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, download_name=f'{tree_uuid}_image.png')


@app.route('/tree/<uuid:tree_uuid>/data', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def data(tree_uuid: str) -> Response:
    success, filename, data = lookyloo.get_data(tree_uuid)
    if not success:
        return make_response(Response('No files.', mimetype='text/text'), 404)

    if filetype.guess_mime(data.getvalue()) is None:
        mime = 'application/octet-stream'
    else:
        mime = filetype.guess_mime(data.getvalue())
    return send_file(data, mimetype=mime,
                     as_attachment=True, download_name=f'{tree_uuid}_{filename}')


@app.route('/tree/<uuid:tree_uuid>/thumbnail/', defaults={'width': 64}, methods=['GET'])
@app.route('/tree/<uuid:tree_uuid>/thumbnail/<int:width>', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def thumbnail(tree_uuid: str, width: int) -> Response:
    to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=False, width=width)
    return send_file(to_return, mimetype='image/png')


@app.route('/tree/<uuid:tree_uuid>/html', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def html(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_html(tree_uuid)
    if success:
        return send_file(to_return, mimetype='text/html',
                         as_attachment=True, download_name=f'{tree_uuid}_page.html')
    return make_response(Response('No HTML available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/cookies', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def cookies(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_cookies(tree_uuid)
    if success:
        return send_file(to_return, mimetype='application/json',
                         as_attachment=True, download_name=f'{tree_uuid}_cookies.json')
    return make_response(Response('No cookies available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/storage_state_download', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def storage_state_download(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_storage_state(tree_uuid)
    if success:
        return send_file(to_return, mimetype='application/json',
                         as_attachment=True, download_name=f'{tree_uuid}_storage_state.json')
    return make_response(Response('No storage state available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/frames_download', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def frames_download(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_frames(tree_uuid)
    if success:
        return send_file(to_return, mimetype='application/json',
                         as_attachment=True, download_name=f'{tree_uuid}_frames.json')
    return make_response(Response('No frames available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/har_download', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def har_download(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_har(tree_uuid)
    if success:
        # The file is gzipped by default unpack and return as json
        return send_file(BytesIO(gzip.decompress(to_return.getvalue())), mimetype='application/json',
                         as_attachment=True, download_name=f'{tree_uuid}_har.json')
    return make_response(Response('No storage state available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def hashes_tree(tree_uuid: str) -> Response:
    success, hashes = lookyloo.get_hashes(tree_uuid)
    if success:
        return send_file(BytesIO('\n'.join(hashes).encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'{tree_uuid}_hashes.txt')
    return make_response(Response('No hashes available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/export', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def export(tree_uuid: str) -> Response:
    success, to_return = lookyloo.get_capture(tree_uuid)
    if success:
        return send_file(to_return, mimetype='application/zip',
                         as_attachment=True, download_name=f'{tree_uuid}_capture.zip')
    return make_response(Response('No capture available.', mimetype='text/text'), 404)


@app.route('/tree/<uuid:tree_uuid>/urls_rendered_page', methods=['GET'])
def urls_rendered_page(tree_uuid: str) -> WerkzeugResponse | str | Response:
    try:
        urls = lookyloo.get_urls_rendered_page(tree_uuid)
        guessed_urls = lookyloo.get_guessed_urls(tree_uuid)
        return render_template('urls_rendered.html', base_tree_uuid=tree_uuid,
                               urls=urls, guessed_urls=guessed_urls)
    except LookylooException:
        flash('Unable to find the rendered node in this capture, cannot get the URLs.', 'error')
        return render_template('urls_rendered.html', error='Unable to find the rendered node in this capture.')
    except Exception as e:
        logger.warning(f'Unable to get URLs: {e}')
        flash('Unable to find the rendered node in this capture.', 'error')
        return render_template('urls_rendered.html', error='Unable to find the rendered node in this capture.')


@app.route('/tree/<uuid:tree_uuid>/hashlookup', methods=['GET'])
def hashlookup(tree_uuid: str) -> str | WerkzeugResponse | Response:
    try:
        merged, total_ressources = lookyloo.merge_hashlookup_tree(tree_uuid,
                                                                  as_admin=flask_login.current_user.is_authenticated)
        # We only want unique URLs for the template
        for sha1, entries in merged.items():
            entries['nodes'] = {node.name for node in entries['nodes']}
    except Exception:  # error or module not enabled
        merged = {}
        total_ressources = 0
    return render_template('hashlookup.html', base_tree_uuid=tree_uuid, merged=merged, total_ressources=total_ressources)


@app.route('/bulk_captures/<uuid:base_tree_uuid>', methods=['POST'])
def bulk_captures(base_tree_uuid: str) -> WerkzeugResponse | str | Response:
    if flask_login.current_user.is_authenticated:
        user = flask_login.current_user.get_id()
    else:
        user = src_request_ip(request)
    cache = lookyloo.capture_cache(base_tree_uuid)
    if not cache:
        flash('Unable to find capture {base_tree_uuid} in cache.', 'error')
        return redirect(url_for('tree', tree_uuid=base_tree_uuid))

    urls_to_capture: list[str] = []
    if selected_urls := request.form.getlist('url'):
        _urls = lookyloo.get_urls_rendered_page(base_tree_uuid)
        urls_to_capture += [_urls[int(selected_id) - 1] for selected_id in selected_urls]
    if selected_urls_guessed := request.form.getlist('guessed_url'):
        _urls = lookyloo.get_guessed_urls(base_tree_uuid)
        urls_to_capture += [_urls[int(selected_id) - 1] for selected_id in selected_urls_guessed]
    if user_urls := request.form.get('user_urls'):
        urls_to_capture += user_urls.strip().split('\n')

    if not urls_to_capture:
        flash('Please provide URLs to capture, none were selected.', 'warning')
        return redirect(url_for('tree', tree_uuid=base_tree_uuid))

    cookies: list[dict[str, str | bool]] = []
    storage_state: dict[str, Any] = {}
    success, storage_state_file = lookyloo.get_storage_state(base_tree_uuid)
    if success:
        if storage_state_content := storage_state_file.getvalue():
            storage_state = orjson.loads(storage_state_content)
    if not storage_state:
        # Old way of doing it, the cookies are in the storage
        success, _cookies = lookyloo.get_cookies(base_tree_uuid)
        if success:
            cookies = load_cookies(_cookies)
    original_capture_settings = lookyloo.get_capture_settings(base_tree_uuid)
    bulk_captures = []
    for url in urls_to_capture:
        if original_capture_settings:
            capture = original_capture_settings.model_copy(
                update={
                    'url': url,
                    'cookies': cookies,
                    'storage': storage_state,
                    'referer': cache.redirects[-1] if cache.redirects else cache.url,
                    'user_agent': cache.user_agent,
                    'parent': base_tree_uuid,
                    'listing': False if cache and cache.no_index else True
                })
        else:
            _capture: dict[str, Any] = {
                'url': url,
                'cookies': cookies,
                'storage': storage_state,
                'referer': cache.redirects[-1] if cache.redirects else cache.url,
                'user_agent': cache.user_agent,
                'parent': base_tree_uuid,
                'listing': False if cache and cache.no_index else True
            }
            capture = CaptureSettings(**_capture)
        new_capture_uuid = lookyloo.enqueue_capture(capture, source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
        bulk_captures.append((new_capture_uuid, url))

    return render_template('bulk_captures.html', uuid=base_tree_uuid, bulk_captures=bulk_captures)


@app.route('/tree/<uuid:tree_uuid>/hide', methods=['GET'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def hide_capture(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.hide_capture(tree_uuid)
    flash('Successfully hidden.', 'success')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/remove', methods=['GET'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def remove_capture(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.remove_capture(tree_uuid)
    flash(f'{tree_uuid} successfully removed.', 'success')
    return redirect(url_for('index'))


@app.route('/tree/<uuid:tree_uuid>/rebuild')
@flask_login.login_required  # type: ignore[untyped-decorator]
def rebuild_tree(tree_uuid: str) -> WerkzeugResponse:
    try:
        lookyloo.remove_pickle(tree_uuid)
        flash('Successfully rebuilt.', 'success')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    except Exception:
        return redirect(url_for('index'))


@app.route('/tree/<uuid:tree_uuid>/cache', methods=['GET'])
def cache_tree(tree_uuid: str) -> WerkzeugResponse:
    lookyloo.capture_cache(tree_uuid)
    return redirect(url_for('index'))


@app.route('/tree/<uuid:tree_uuid>/monitor', methods=['POST', 'GET'])
def monitor(tree_uuid: str) -> WerkzeugResponse:
    if not lookyloo.monitoring:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    if request.form.get('name') or not request.form.get('confirm'):
        # got a bot.
        logger.debug(f'{src_request_ip(request)} is a bot - {request.headers.get("User-Agent")}.')
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


@app.route('/tree/<uuid:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str) -> WerkzeugResponse:
    if not enable_mail_notification:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    if request.form.get('name') or not request.form.get('confirm'):
        # got a bot.
        logger.debug(f'{src_request_ip(request)} is a bot - {request.headers.get("User-Agent")}.')
        return redirect('https://www.youtube.com/watch?v=iwGFalTRHDA')

    email: str = request.form['email'] if request.form.get('email') else ''
    if '@' not in email:
        # skip clearly incorrect emails
        email = ''
    comment: str = request.form['comment'] if request.form.get('comment') else ''
    send_status = lookyloo.send_mail(tree_uuid, as_admin=flask_login.current_user.is_authenticated, email=email, comment=comment)
    if not send_status:
        flash("Unable to send email notification.", 'error')
    elif isinstance(send_status, dict) and 'error' in send_status:
        flash(f"Unable to send email: {send_status['error']}", 'error')
    else:
        flash("Email notification sent", 'success')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>/trigger_indexing', methods=['POST', 'GET'])
def trigger_indexing(tree_uuid: str) -> WerkzeugResponse:
    if not lookyloo.index_capture(tree_uuid):
        flash("Unable to index the tree, see logs.", 'error')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<uuid:tree_uuid>', methods=['GET'])
@app.route('/tree/<uuid:tree_uuid>/<uuid:node_uuid>', methods=['GET'])
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
        success, screenshot = lookyloo.get_screenshot(tree_uuid)
        if success:
            screenshot_size = screenshot.getbuffer().nbytes
        else:
            screenshot_size = 0
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
                    logger.info(f'Invalid uuid ({e}): {node_uuid}')
        if cache.error:
            flash(cache.error, 'warning')

        monitoring_collections: list[str] = []
        monitoring_settings: dict[str, int | bool] = {}
        if lookyloo.monitoring:
            try:
                monitoring_collections = lookyloo.monitoring.collections()
            except Exception as e:
                flash(Markup('Unable to get existing connections from the monitoring : {}').format(e), 'warning')
            try:
                monitoring_settings = lookyloo.monitoring.instance_settings()  # type: ignore[assignment]
            except Exception as e:
                flash(Markup('Unable to initialize the monitoring instance: {}').format(e), 'warning')

        # Check if the capture has been indexed yet. Print a warning if not.
        capture_indexed = all(get_indexing(flask_login.current_user).capture_indexed(tree_uuid))
        if not capture_indexed:
            flash('The capture has not been indexed yet. Some correlations will be missing.', 'warning')

        has_downloads, _, _ = lookyloo.get_data(tree_uuid)
        if has_downloads:
            flash('Download(s) have been triggered during the capture. View them in Capture > Downloads.', 'info')

        return render_template('tree.html', tree_json=ct.to_json(),
                               info=cache,
                               tree_uuid=tree_uuid, public_domain=lookyloo.public_domain,
                               screenshot_thumbnail=b64_thumbnail, page_title=cache.title if hasattr(cache, 'title') else '',
                               favicon=b64_potential_favicon,
                               mime_favicon=mime_favicon,
                               screenshot_size=screenshot_size,
                               meta=meta, enable_mail_notification=enable_mail_notification,
                               enable_monitoring=bool(lookyloo.monitoring),
                               ignore_sri=ignore_sri,
                               monitoring_settings=monitoring_settings,
                               monitoring_collections=monitoring_collections,
                               enable_context_by_users=enable_context_by_users,
                               enable_categorization=enable_categorization,
                               enable_bookmark=enable_bookmark,
                               misp_push=lookyloo.misps.available and lookyloo.misps.has_push(flask_login.current_user.is_authenticated),
                               misp_lookup=lookyloo.misps.available and lookyloo.misps.has_lookup(flask_login.current_user.is_authenticated),
                               blur_screenshot=blur_screenshot, urlnode_uuid=hostnode_to_highlight,
                               auto_trigger_modules=auto_trigger_modules,
                               confirm_message=confirm_message if confirm_message else 'Tick to confirm.',
                               parent_uuid=cache.parent,
                               has_redirects=True if cache.redirects else False,
                               has_downloads=has_downloads,
                               capture_indexed=capture_indexed,
                               capture_settings=capture_settings.model_dump(exclude_none=True) if capture_settings else {})

    except (NoValidHarFile, TreeNeedsRebuild) as e:
        logger.info(f'[{tree_uuid}] The capture exists, but we cannot use the HAR files: {e}')
        flash(Markup('Unable to build a tree for {uuid}: {error}.').format(uuid=tree_uuid, error=cache.error), 'warning')
        return index_generic()
    finally:
        lookyloo.update_tree_cache_info(os.getpid(), 'website')


@app.route('/tree/<uuid:tree_uuid>/mark_as_legitimate', methods=['POST'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def mark_as_legitimate(tree_uuid: str) -> Response:
    if request.data:
        legitimate_entries: dict[str, Any] = request.get_json(force=True)
        lookyloo.add_to_legitimate(tree_uuid, **legitimate_entries)
    else:
        lookyloo.add_to_legitimate(tree_uuid)
    return jsonify({'message': 'Legitimate entry added.'})


@app.route('/tree/<uuid:tree_uuid>/identifiers', methods=['GET'])
def tree_identifiers(tree_uuid: str) -> str:
    return render_template('tree_identifiers.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/favicons', methods=['GET'])
def tree_favicons(tree_uuid: str) -> str:
    return render_template('tree_favicons.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/hashes_types', methods=['GET'])
def tree_capture_hashes_types(tree_uuid: str) -> str:
    return render_template('tree_hashes_types.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/body_hashes', methods=['GET'])
def tree_body_hashes(tree_uuid: str) -> str:
    return render_template('tree_body_hashes.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/ips', methods=['GET'])
def tree_ips(tree_uuid: str) -> str:
    proxified = False
    if cache := lookyloo.capture_cache(tree_uuid):
        if cache.capture_settings and cache.capture_settings.proxy:
            proxified = True
    return render_template('tree_ips.html', tree_uuid=tree_uuid, proxified=proxified)


@app.route('/tree/<uuid:tree_uuid>/hostnames', methods=['GET'])
def tree_hostnames(tree_uuid: str) -> str:
    return render_template('tree_hostnames.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/urls', methods=['GET'])
def tree_urls(tree_uuid: str) -> str:
    return render_template('tree_urls.html', tree_uuid=tree_uuid)


@app.route('/tree/<uuid:tree_uuid>/pandora', methods=['GET', 'POST'])
def pandora_submit(tree_uuid: str) -> dict[str, Any] | Response:
    if not lookyloo.pandora.available:
        return {'error': 'Pandora not available.'}
    node_uuid = None
    if request.method == 'POST':
        input_json = request.get_json(force=True)
        # Submit a ressource from the capture / rendering of the page
        node_uuid = input_json.get('node_uuid')
        h_request = input_json.get('ressource_hash')
        # Submit a downloaded file
        index_in_zip = input_json.get('index_in_zip')
    if node_uuid:
        ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_request)
        if ressource:
            filename, content, mimetype = ressource
        elif h_request:
            return {'error': 'Unable to find resource {h_request} in node {node_uuid} of tree {tree_uuid}'}
        else:
            return {'error': 'Unable to find resource in node {node_uuid} of tree {tree_uuid}'}
    elif index_in_zip:
        # Submit a file from the zip
        _i = int(index_in_zip)
        success, filename, content = lookyloo.get_data(tree_uuid, index_in_zip=_i)
        if not success or not filename or not content:
            return {'error': f'Unable to find file {_i} in tree {tree_uuid}'}
    else:
        success, filename, content = lookyloo.get_data(tree_uuid)

    response = lookyloo.pandora.submit_file(content, filename)
    return jsonify(response)


# ##### helpers #####

def index_generic(show_hidden: bool=False, show_error: bool=True, category: str | None=None) -> str:
    """This method is used to generate the index page. It is possible that some of the captures
    do not have their pickle yet.

    We must assume that calling cached.tree will fail, and handle it gracefully.
    """
    mastodon_domain = None
    mastodon_botname = None
    if get_config('mastobot', 'enable'):
        mastodon_domain = get_config('mastobot', 'domain')
        mastodon_botname = get_config('mastobot', 'botname')
    return render_template('index.html', public_domain=lookyloo.public_domain,
                           show_hidden=show_hidden,
                           category=category,
                           show_project_page=get_config('generic', 'show_project_page'),
                           enable_takedown_form=get_config('generic', 'enable_takedown_form'),
                           mastobot_enabled=get_config('mastobot', 'enable'),
                           mastodon_domain=mastodon_domain,
                           mastodon_botname=mastodon_botname,
                           version=pkg_version)


def get_index_params(request: Request) -> tuple[bool, str]:
    show_error: bool = True
    category: str = ''
    if hide_captures_with_error:
        show_error = True if (request.args.get('show_error') and request.args.get('show_error') == 'True') else False

    if enable_categorization:
        category = unquote_plus(request.args['category']) if request.args.get('category') else ''
    return show_error, category


# ##### Index level methods #####

@app.route('/index', methods=['GET'])
def index() -> str:
    show_error, category = get_index_params(request)
    return index_generic(show_error=show_error, category=category)


@app.route('/hidden', methods=['GET'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def index_hidden() -> str:
    show_error, category = get_index_params(request)
    return index_generic(show_hidden=True, show_error=show_error, category=category)


@app.route('/cookies', methods=['GET'])
def cookies_lookup() -> str:
    cookies_names = []
    for name in get_indexing(flask_login.current_user).cookies_names:
        cookies_names.append((name, get_indexing(flask_login.current_user).get_captures_cookie_name_count(name)))
    return render_template('cookies.html', cookies_names=cookies_names)


@app.route('/hhhashes', methods=['GET'])
def hhhashes_lookup() -> str:
    hhhashes = []
    for hhh in get_indexing(flask_login.current_user).http_headers_hashes:
        hhhashes.append((hhh, get_indexing(flask_login.current_user).get_captures_hhhash_count(hhh)))
    return render_template('hhhashes.html', hhhashes=hhhashes)


@app.route('/favicons', methods=['GET'])
def favicons_lookup() -> str:
    favicons = []
    for sha512 in get_indexing(flask_login.current_user).favicons:
        favicon = get_indexing(flask_login.current_user).get_favicon(sha512)
        if not favicon:
            continue
        favicon_b64 = base64.b64encode(favicon).decode()
        nb_captures = get_indexing(flask_login.current_user).get_captures_favicon_count(sha512)
        favicons.append((sha512, nb_captures, favicon_b64))
    return render_template('favicons.html', favicons=favicons)


@app.route('/ressources', methods=['GET'])
def ressources() -> str:
    ressources = []
    for h in get_indexing(flask_login.current_user).ressources:
        freq = get_indexing(flask_login.current_user).get_captures_body_hash_count(h)
        context = lookyloo.context.find_known_content(h)
        # Only get the recent captures
        _, entries = get_indexing(flask_login.current_user).get_captures_body_hash(h, oldest_capture=datetime.now() - timedelta(**time_delta_on_index))
        for capture_uuid in entries:
            url_nodes = get_indexing(flask_login.current_user).get_capture_body_hash_nodes(capture_uuid, h)
            url_node = url_nodes.pop()
            ressource = lookyloo.get_ressource(capture_uuid, url_node, h)
            if not ressource:
                continue
            ressources.append((h, freq, context.get(h), capture_uuid, url_node, ressource[0], ressource[2]))
    return render_template('ressources.html', ressources=ressources)


@app.route('/categories', methods=['GET'])
def categories() -> str:
    categories: list[tuple[str, int]] = []
    for c in get_indexing(flask_login.current_user).categories:
        categories.append((c, get_indexing(flask_login.current_user).get_captures_category_count(c)))
    return render_template('categories.html', categories=categories)


@app.route('/rebuild_all')
@flask_login.login_required  # type: ignore[untyped-decorator]
def rebuild_all() -> WerkzeugResponse:
    lookyloo.rebuild_all()
    return redirect(url_for('index'))


@app.route('/rebuild_cache')
@flask_login.login_required  # type: ignore[untyped-decorator]
def rebuild_cache() -> WerkzeugResponse:
    lookyloo.rebuild_cache()
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
def search() -> str | Response | WerkzeugResponse:
    if request.form.get('url'):
        quoted_url: str = base64.urlsafe_b64encode(request.form.get('url', '').strip().encode()).decode()
        return redirect(url_for('url_details', from_popup=True, url=quoted_url))
    if request.form.get('hostname'):
        return redirect(url_for('hostname_details', from_popup=True, hostname=request.form.get('hostname')))
    if request.form.get('tld'):
        return redirect(url_for('tld_details', from_popup=True, tld=request.form.get('tld')))
    if request.form.get('domain'):
        return redirect(url_for('domain_details', from_popup=True, domain=request.form.get('domain')))
    if request.form.get('ip'):
        return redirect(url_for('ip_details', from_popup=True, ip=request.form.get('ip')))
    if request.form.get('ressource'):
        return redirect(url_for('body_hash_details', from_popup=True, body_hash=request.form.get('ressource')))
    if request.form.get('cookie'):
        return redirect(url_for('cookies_name_detail', from_popup=True, cookie_name=request.form.get('cookie')))
    if request.form.get('favicon_sha512'):
        return redirect(url_for('favicon_detail', from_popup=True, favicon_sha512=request.form.get('favicon_sha512')))
    if 'favicon_file' in request.files:
        favicon = request.files['favicon_file'].stream.read()
        favicon_sha512 = hashlib.sha512(favicon).hexdigest()
        return redirect(url_for('favicon_detail', from_popup=True, favicon_sha512=favicon_sha512))
    return render_template('search.html', version=pkg_version)


def _prepare_capture_template(user_ua: str | None, predefined_settings: dict[str, Any] | None=None, *,
                              user_config: dict[str, Any] | None=None) -> str:
    # if we have multiple remote lacus, get the list of names
    multiple_remote_lacus: dict[str, dict[str, Any]] = {}
    default_remote_lacus = None
    mastodon_domain = None
    mastodon_botname = None
    if get_config('mastobot', 'enable'):
        mastodon_domain = get_config('mastobot', 'domain')
        mastodon_botname = get_config('mastobot', 'botname')

    # If it is forced, no reason to add the checkbox on the UI
    hide_tt_checkbox = get_config('generic', 'force_trusted_timestamp')

    tt_enabled_default = False
    if not hide_tt_checkbox:
        # check if trusted_timestamp should be enabled by default on the UI
        if tt_settings := get_config('generic', 'trusted_timestamp_settings'):
            tt_enabled_default = tt_settings.get('enable_default', False)

    try:
        if isinstance(lookyloo.lacus, dict):
            multiple_remote_lacus = {}
            for remote_lacus_name, _lacus in lookyloo.lacus.items():
                if not _lacus.is_up:
                    logger.warning(f'Lacus "{remote_lacus_name}" is not up.')
                    continue
                multiple_remote_lacus[remote_lacus_name] = {}
                try:
                    if proxies := _lacus.proxies():
                        # We might have other settings in the future.
                        multiple_remote_lacus[remote_lacus_name]['proxies'] = proxies
                except Exception as e:
                    # We cannot connect to Lacus, skip it.
                    logger.warning(f'Unable to get proxies from Lacus "{remote_lacus_name}": {e}.')
                    continue

            default_remote_lacus = get_config('generic', 'multiple_remote_lacus').get('default')
        elif isinstance(lookyloo.lacus, PyLacus):
            if not lookyloo.lacus.is_up:
                logger.warning('Remote Lacus is not up.')
            else:
                multiple_remote_lacus = {'default': {}}
                try:
                    if proxies := lookyloo.lacus.proxies():
                        # We might have other settings in the future.
                        multiple_remote_lacus['default']['proxies'] = proxies
                except Exception as e:
                    logger.warning(f'Unable to get proxies from Lacus: {e}.')
            default_remote_lacus = 'default'
    except ConfigError as e:
        logger.warning(f'Unable to get remote lacus settings: {e}.')
        flash('The capturing system is down, you can enqueue a capture and it will start ASAP.', 'error')

    # NOTE: Inform user if none of the remote lacuses are up?
    return render_template('capture.html', user_agents=user_agents.user_agents,
                           default=user_agents.default,
                           personal_ua=user_ua,
                           default_public=get_config('generic', 'default_public'),
                           public_domain=lookyloo.public_domain,
                           devices=lookyloo.get_playwright_devices(),
                           predefined_settings=predefined_settings if predefined_settings else {},
                           user_config=user_config,
                           show_project_page=get_config('generic', 'show_project_page'),
                           version=pkg_version,
                           headed_allowed=lookyloo.headed_allowed,
                           tt_enabled_default=tt_enabled_default,
                           hide_tt_checkbox=hide_tt_checkbox,
                           multiple_remote_lacus=multiple_remote_lacus,
                           default_remote_lacus=default_remote_lacus,
                           mastobot_enabled=get_config('mastobot', 'enable'),
                           mastodon_domain=mastodon_domain,
                           mastodon_botname=mastodon_botname,
                           has_global_proxy=True if lookyloo.global_proxy else False,
                           categories=sorted(get_indexing(flask_login.current_user).categories))


@app.route('/recapture/<uuid:tree_uuid>', methods=['GET'])
def recapture(tree_uuid: str) -> str | Response | WerkzeugResponse:
    cache = lookyloo.capture_cache(tree_uuid)
    if cache and hasattr(cache, 'capture_dir'):
        if capture_settings := lookyloo.get_capture_settings(tree_uuid):
            return _prepare_capture_template(user_ua=request.headers.get('User-Agent'),
                                             predefined_settings=capture_settings.model_dump(exclude_none=True))
    flash(f'Unable to find the capture {tree_uuid} in the cache.', 'error')
    return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))


@app.route('/ressource_by_hash/<sha512:sha512>', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def ressource_by_hash(sha512: str) -> Response:
    content_fallback = f'Unable to find "{sha512}"'
    if uuids := get_indexing(flask_login.current_user).get_hash_uuids(sha512):
        # got UUIDs for this hash
        capture_uuid, urlnode_uuid = uuids
        content_fallback += f' in capture "{capture_uuid}" and node "{urlnode_uuid}"'
        if ressource := lookyloo.get_ressource(capture_uuid, urlnode_uuid, sha512):
            filename, body, mimetype = ressource
            return send_file(body, as_attachment=True, download_name=filename)

    return send_file(BytesIO(content_fallback.encode()), as_attachment=True, download_name='Unknown_Hash.txt')


# ################## Submit existing capture ##################

def __get_remote_capture(remote_lookyloo: str, remote_uuid: str) -> Markup | BytesIO:
    pylookyloo = PyLookyloo(remote_lookyloo)
    if not pylookyloo.is_up:
        return Markup('Unable to connect to "{}".').format(remote_lookyloo)
    status = pylookyloo.get_status(remote_uuid).get('status_code')
    if status == -1:
        return Markup('Unknown capture "{}" from "{}".').format(remote_uuid, remote_lookyloo)
    if status in [0, 2]:
        return Markup('Capture "{}" from "{}" is not ready yet, please retry later.').format(remote_uuid, remote_lookyloo)
    if status != 1:
        return Markup('Unknown status "{}" for capture "{}" from "{}".').format(status, remote_uuid, remote_lookyloo)
    # Lookyloo is up, and the capture exists
    return pylookyloo.get_complete_capture(remote_uuid)


@app.route('/submit_capture', methods=['GET', 'POST'])
def submit_capture() -> str | Response | WerkzeugResponse:
    listing: bool = True if request.form.get('listing') else False
    messages: dict[str, list[str]] = {'errors': [], 'warnings': []}
    new_uuid: str = ''

    if request.method == 'POST':
        if request.form.get('pull_capture_domain') and request.form.get('pull_capture_uuid'):
            remote_capture = __get_remote_capture(request.form['pull_capture_domain'],
                                                  request.form['pull_capture_uuid'])
            if isinstance(remote_capture, str):
                messages['errors'].append(remote_capture)
            else:
                new_uuid, messages = lookyloo.unpack_full_capture_archive(remote_capture, listing)

        elif 'full_capture' in request.files and request.files['full_capture']:
            # it *only* accepts a lookyloo export.
            full_capture_file = BytesIO(request.files['full_capture'].stream.read())
            new_uuid, messages = lookyloo.unpack_full_capture_archive(full_capture_file, listing)

        elif 'har_file' in request.files and request.files['har_file']:
            har: dict[str, Any] | None = None
            html: str | None = None
            last_redirected_url: str | None = None
            screenshot: bytes | None = None

            har = orjson.loads(request.files['har_file'].stream.read())
            last_redirected_url = request.form.get('landing_page')
            if 'screenshot_file' in request.files:
                screenshot = request.files['screenshot_file'].stream.read()
            if 'html_file' in request.files:
                html = request.files['html_file'].stream.read().decode()
            try:
                new_uuid = str(uuid4())
                lookyloo.store_capture(new_uuid, is_public=listing, har=har,
                                       last_redirected_url=last_redirected_url,
                                       png=screenshot, html=html)
            except Exception as e:
                messages['errors'].append(f'Unable to store the capture: {e}')

        else:
            messages['errors'].append('Invalid submission: please submit at least an HAR file.')

        if 'errors' in messages and messages['errors']:
            # Got an error, no tree to redirect to.
            for error in messages['errors']:
                flash(escape(error), 'error')
        else:
            if 'warnings' in messages and messages['warnings']:
                for warning in messages['warnings']:
                    flash(escape(warning), 'warning')

            if new_uuid:
                # Got a new capture
                return redirect(url_for('tree', tree_uuid=new_uuid))

    return render_template('submit_capture.html',
                           default_public=get_config('generic', 'default_public'),
                           public_domain=lookyloo.public_domain)


# #############################################################

@app.route('/capture', methods=['GET', 'POST'])
def capture_web() -> str | Response | WerkzeugResponse:
    user_config: dict[str, Any] | None = None
    if flask_login.current_user.is_authenticated:
        user = flask_login.current_user.get_id()
        user_config = load_user_config(user)
    else:
        user = src_request_ip(request)

    if request.method == 'POST':
        if not (request.form.get('url') or request.form.get('urls') or 'document' in request.files):
            flash('Invalid submission: please submit at least a URL or a document.', 'error')
            return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))

        capture_query: dict[str, Any] = {}
        # check if the post request has the file part
        if 'cookies' in request.files and request.files['cookies'].filename:
            capture_query['cookies'] = load_cookies(request.files['cookies'].stream.read())
        if 'storage_state' in request.files and request.files['storage_state'].filename:
            if _storage := request.files['storage_state'].stream.read():
                try:
                    capture_query['storage'] = orjson.loads(_storage)
                except orjson.JSONDecodeError:
                    flash(Markup('Invalid storage state: must be a JSON: {}.').format(_storage.decode()), 'error')
                    logger.info(f'Invalid storage state: must be a JSON: {_storage.decode()}.')

        if request.form.get('device_name'):
            capture_query['device_name'] = request.form['device_name']
        elif request.form.get('freetext_ua'):
            capture_query['user_agent'] = request.form['freetext_ua']
        elif request.form.get('personal_ua') and request.headers.get('User-Agent'):
            capture_query['user_agent'] = request.headers['User-Agent']
        else:
            capture_query['user_agent'] = request.form['user_agent']
            capture_query['os'] = request.form['os']
            browser = request.form['browser']
            if browser in ['chromium', 'firefox', 'webkit']:
                # Will be guessed otherwise.
                capture_query['browser'] = browser

        capture_query['listing'] = True if request.form.get('listing') else False
        capture_query['allow_tracking'] = True if request.form.get('allow_tracking') else False
        capture_query['with_trusted_timestamps'] = True if request.form.get('with_trusted_timestamps') else False
        capture_query['java_script_enabled'] = True if request.form.get('java_script_enabled') else False

        if request.form.get('width') or request.form.get('height'):
            capture_query['viewport'] = {'width': int(request.form.get('width', 1280)),
                                         'height': int(request.form.get('height', 720))}

        if lookyloo.headed_allowed:
            capture_query['headless'] = True if request.form.get('headless') else False

        if request.form.get('general_timeout_in_sec'):
            capture_query['general_timeout_in_sec'] = request.form['general_timeout_in_sec']

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

        if request.form.get('init_script'):
            capture_query['init_script'] = request.form['init_script']

        if request.form.get('categories'):
            capture_query['categories'] = request.form.getlist('categories')

        capture_query['remote_lacus_name'] = request.form.get('remote_lacus_name')
        if _p_name := [n for n in request.form.getlist('remote_lacus_proxy_name') if n]:
            capture_query['proxy'] = _p_name[0]
        elif request.form.get('proxy'):
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
                }

        if request.form.get('url'):
            capture_query['url'] = request.form['url']
            perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**capture_query), source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
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
                new_capture_uuid = lookyloo.enqueue_capture(CaptureSettings(**query), source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
                bulk_captures.append((new_capture_uuid, url))

            return render_template('bulk_captures.html', bulk_captures=bulk_captures)
        elif 'document' in request.files:
            # File upload
            capture_query['document'] = base64.b64encode(request.files['document'].stream.read()).decode()
            if request.files['document'].filename:
                capture_query['document_name'] = request.files['document'].filename
            else:
                capture_query['document_name'] = 'unknown_name.bin'
            perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**capture_query), source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
            time.sleep(2)
            return redirect(url_for('tree', tree_uuid=perma_uuid))
        else:
            flash('Invalid submission: please submit at least a URL or a document.', 'error')
    elif request.method == 'GET' and request.args.get('url'):
        url = unquote_plus(request.args['url']).strip()
        capture_query = {'url': url}
        perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**capture_query), source='web', user=user, authenticated=flask_login.current_user.is_authenticated)
        return redirect(url_for('tree', tree_uuid=perma_uuid))

    # render template
    return _prepare_capture_template(user_ua=request.headers.get('User-Agent'),
                                     user_config=user_config)


@app.route('/simple_capture', methods=['GET', 'POST'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def simple_capture() -> str | Response | WerkzeugResponse:
    user = flask_login.current_user.get_id()
    if request.method == 'POST':
        if not (request.form.get('url') or request.form.get('urls')):
            flash('Invalid submission: please submit at least a URL.', 'error')
            return render_template('simple_capture.html')
        capture_query: dict[str, Any] = {}
        if request.form.get('url'):
            capture_query['url'] = request.form['url']
            perma_uuid = lookyloo.enqueue_capture(CaptureSettings(**capture_query), source='web', user=user,
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
                new_capture_uuid = lookyloo.enqueue_capture(CaptureSettings(**query), source='web', user=user,
                                                            authenticated=flask_login.current_user.is_authenticated)
                if new_capture_uuid:
                    flash('Recording is in progress and is reported automatically.', 'success')
            return redirect(url_for('simple_capture'))
    # render template
    return render_template('simple_capture.html')


@app.route('/cookies/<string:cookie_name>', methods=['GET'])
def cookies_name_detail(cookie_name: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('cookie_name.html', cookie_name=cookie_name, from_popup=from_popup)


@app.route('/hhhdetails/<string:hhh>', methods=['GET'])
def hhh_detail(hhh: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    headers: list[tuple[str, str]] = []
    if capture_node := get_indexing(flask_login.current_user).get_node_for_headers(hhh):
        capture_uuid, node_uuid = capture_node
        if urlnode := lookyloo.get_urlnode_from_tree(capture_uuid, node_uuid):
            headers = [(header["name"], header["value"]) for header in urlnode.response['headers']]
    return render_template('hhh_details.html', hhh=hhh, headers=headers, from_popup=from_popup)


@app.route('/identifier_details/<string:identifier_type>/<string:identifier>', methods=['GET'])
def identifier_details(identifier_type: str, identifier: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('identifier_details.html', identifier_type=identifier_type,
                           identifier=identifier, from_popup=from_popup)


@app.route('/capture_hash_details/<string:hash_type>/<string:h>', methods=['GET'])
def capture_hash_details(hash_type: str, h: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('hash_type_details.html', hash_type=hash_type, h=h, from_popup=from_popup)


@app.route('/favicon_details/<sha512:favicon_sha512>', methods=['GET'])
def favicon_detail(favicon_sha512: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    favicon = get_indexing(flask_login.current_user).get_favicon(favicon_sha512)
    if favicon:
        mimetype = from_string(favicon, mime=True)
        b64_favicon = base64.b64encode(favicon).decode()
        mmh3_shodan = lookyloo.compute_mmh3_shodan(favicon)
    else:
        mimetype = ''
        b64_favicon = ''
        mmh3_shodan = ''
    return render_template('favicon_details.html',
                           mimetype=mimetype, b64_favicon=b64_favicon,
                           mmh3_shodan=mmh3_shodan,
                           favicon_sha512=favicon_sha512,
                           from_popup=from_popup)


@app.route('/body_hashes/<sha512:body_hash>', methods=['GET'])
def body_hash_details(body_hash: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    filename = ''
    mimetype = ''
    b64 = ''
    capture_uuid = ''
    urlnode_uuid = ''
    ressource_size = 0
    if uuids := get_indexing(flask_login.current_user).get_hash_uuids(body_hash):
        # got UUIDs for this hash
        capture_uuid, urlnode_uuid = uuids
        if ressource := lookyloo.get_ressource(capture_uuid, urlnode_uuid, body_hash):
            filename, body, mimetype = ressource
            ressource_size = body.getbuffer().nbytes
            if mimetype_to_generic(mimetype) == 'image':
                b64 = base64.b64encode(body.read()).decode()
    return render_template('body_hash.html', body_hash=body_hash, from_popup=from_popup,
                           filename=filename, ressource_size=ressource_size, mimetype=mimetype, b64=b64,
                           has_pandora=lookyloo.pandora.available,
                           sample_tree_uuid=capture_uuid, sample_node_uuid=urlnode_uuid)


@app.route('/urls/<string:url>', methods=['GET'])
def url_details(url: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    url_unquoted = base64.urlsafe_b64decode(url.strip()).decode()
    return render_template('url.html', url=url_unquoted, url_quoted=url, from_popup=from_popup)


@app.route('/hostnames/<string:hostname>', methods=['GET'])
def hostname_details(hostname: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('hostname.html', hostname=hostname, from_popup=from_popup)


@app.route('/tlds/<string:tld>', methods=['GET'])
def tld_details(tld: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('tld.html', tld=tld, from_popup=from_popup)


@app.route('/domains/<string:domain>', methods=['GET'])
def domain_details(domain: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('domain.html', domain=domain, from_popup=from_popup)


@app.route('/ips/<string:ip>', methods=['GET'])
def ip_details(ip: str) -> str:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    return render_template('ip.html', ip=ip, from_popup=from_popup)


@app.route('/stats', methods=['GET'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def statsfull() -> str:
    # only available to logged in users, get all the captures
    stats = lookyloo.get_stats(public=False)
    return render_template('stats.html', stats=stats, version=pkg_version)


@app.route('/whois/<string:query>', methods=['GET'])
@app.route('/whois/<string:query>/<int:email_only>', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def whois(query: str, email_only: int=0) -> Response:
    to_return = lookyloo.uwhois.whois(query, bool(email_only))
    if isinstance(to_return, str):
        return send_file(BytesIO(to_return.encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'whois.{query}.txt')
    return jsonify(to_return)


# ##### Methods related to a specific URLNode #####

@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/request_cookies', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def urlnode_request_cookies(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.request_cookie:
        return None

    return send_file(BytesIO(orjson.dumps(urlnode.request_cookie, option=orjson.OPT_INDENT_2)),
                     mimetype='text/plain', as_attachment=True, download_name=f'{tree_uuid}_{node_uuid}_request_cookies.txt')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/response_cookies', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def urlnode_response_cookies(tree_uuid: str, node_uuid: str) -> Response | None:
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.response_cookie:
        return None

    return send_file(BytesIO(orjson.dumps(urlnode.response_cookie, option=orjson.OPT_INDENT_2)),
                     mimetype='text/plain', as_attachment=True, download_name=f'{tree_uuid}_{node_uuid}_response_cookies.txt')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/urls_in_rendered_content', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
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
                     as_attachment=True, download_name=f'{tree_uuid}_urls_in_rendered_content.txt')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/rendered_content', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def urlnode_rendered_content(tree_uuid: str, node_uuid: str) -> Response | None:
    try:
        urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    except IndexError:
        to_send = b"Unable to find rendered content, the tree seem to be broken. Please reload the page and try again."
        lookyloo.remove_pickle(tree_uuid)
        return send_file(BytesIO(to_send), mimetype='text/plain',
                         as_attachment=True, download_name=f'{tree_uuid}_rendered_content.txt')
    if not urlnode.rendered_html:
        return None
    return send_file(BytesIO(urlnode.rendered_html.getvalue()), mimetype='text/plain',
                     as_attachment=True, download_name=f'{tree_uuid}_rendered_content.txt')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/posted_data', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def urlnode_post_request(tree_uuid: str, node_uuid: str) -> WerkzeugResponse | str | Response | None:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    render_in_modal = True if (request.args.get('render_in_modal') and request.args.get('render_in_modal') == 'True') else False
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)

    if render_in_modal:
        # return modal
        return render_template('prettify_text.html',
                               download_link=url_for('urlnode_post_request', tree_uuid=tree_uuid, node_uuid=node_uuid),
                               post_info=urlnode.posted_data_info if 'posted_data_info' in urlnode.features else None,
                               from_popup=from_popup)

    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.posted_data:
        return None

    posted: str | bytes
    if isinstance(urlnode.posted_data, (dict, list)):
        # JSON blob, pretty print.
        posted = orjson.dumps(urlnode.posted_data, option=orjson.OPT_INDENT_2).decode()
    else:
        posted = urlnode.posted_data

    if isinstance(posted, str):
        to_return = BytesIO(posted.encode())
    else:
        to_return = BytesIO(posted)

    if isinstance(posted, str):
        return send_file(to_return, mimetype='text/plain',
                         as_attachment=True, download_name=f'{tree_uuid}_{node_uuid}_posted_data.txt')
    else:
        return send_file(to_return, mimetype='application/octet-stream',
                         as_attachment=True, download_name=f'{tree_uuid}_{node_uuid}_posted_data.bin')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/ressource', methods=['POST', 'GET'])
@file_response  # type: ignore[untyped-decorator]
def get_ressource(tree_uuid: str, node_uuid: str) -> WerkzeugResponse | str | Response:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    render_in_modal = True if (request.args.get('render_in_modal') and request.args.get('render_in_modal') == 'True') else False
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
    if render_in_modal:
        # return modal
        return render_template('prettify_text.html',
                               download_link=url_for('get_ressource', tree_uuid=tree_uuid, node_uuid=node_uuid),
                               from_popup=from_popup)
    else:
        return send_file(to_return, mimetype=mimetype, as_attachment=True, download_name=filename)


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/ressource_preview', methods=['GET'])
@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/ressource_preview/<sha512:h_ressource>', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def get_ressource_preview(tree_uuid: str, node_uuid: str, h_ressource: str | None=None) -> Response:
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_ressource)
    if not ressource:
        return Response('No preview available.', mimetype='text/text')
    filename, r, mimetype = ressource
    if mimetype.startswith('image'):
        return send_file(r, mimetype=mimetype,
                         as_attachment=True, download_name=filename)
    return Response('No preview available.', mimetype='text/text')


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/hashes', methods=['GET'])
@file_response  # type: ignore[untyped-decorator]
def hashes_urlnode(tree_uuid: str, node_uuid: str) -> Response:
    success, hashes = lookyloo.get_hashes(tree_uuid, urlnode_uuid=node_uuid)
    if success:
        return send_file(BytesIO('\n'.join(hashes).encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'{tree_uuid}_{node_uuid}_hashes.txt')
    return make_response('Unable to find the hashes.', 404)


@app.route('/tree/<uuid:tree_uuid>/url/<uuid:node_uuid>/add_context', methods=['POST'])
@flask_login.login_required  # type: ignore[untyped-decorator]
def add_context(tree_uuid: str, node_uuid: str) -> WerkzeugResponse | None:
    if not enable_context_by_users:
        return redirect(url_for('ressources'))

    context_data = request.form
    ressource_hash: str = context_data['hash_to_contextualize']
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
        hostnode_uuid = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid).hostnode_uuid
        return redirect(url_for('hostnode_popup', tree_uuid=tree_uuid, node_uuid=hostnode_uuid))
    elif callback_str == 'ressources':
        return redirect(url_for('ressources'))
    return None


node_view_template = app.jinja_env.from_string(source='''
The capture contains this value in <b>{{nodes | length}}</b> nodes.
<br>
<p class="d-inline-flex gap-1">
  <button class="btn btn-link" type="button"
      data-bs-toggle="collapse" data-bs-target="#collapseAllNodes_{{collapse_id}}"
      aria-expanded="false" aria-controls="collapseAllNodes_{{collapse_id}}">
  Show
  </button>
</p>
<div class="collapse" id="collapseAllNodes_{{collapse_id}}">
  <div class="card card-body">
    Click on the link to go directly on the node in the tree.
    <span class="d-inline-block text-break">
      <ul class="list-group list-group-flush">
        {%for n in nodes %}
        {% if n|length == 2 %}
        {% set url, node = n %}
        {% set extra = None %}
        {% else %}
        {% set url, node, extra = n %}
        {% endif %}
        <li class="list-group-item">
          {% if from_popup %}
          <a href="#" class="openNewTab" data-capture="{{capture_uuid}}" data-hostnode="{{node}}">
            {{shorten_string(url)}}
          </a>
          {% else %}
          <a href="{{url_for("tree", tree_uuid=capture_uuid, node_uuid=node)}}">
            {{shorten_string(url)}}
          </a>
          {% endif %}
          {% if extra %}
          <b>{{extra}}</b>
          {% endif %}
        </li>
        {% endfor %}
      </ul>
    </span>
  </div>
</div>
''')


def __prepare_node_view(capture_uuid: str, nodes: Sequence[tuple[str, str] | tuple[str, str, str | None]], from_popup: bool=False) -> dict[str, str]:
    return {'display': render_template(node_view_template, collapse_id=str(uuid4()), nodes=nodes, capture_uuid=capture_uuid),
            'filter': escape(' '.join(n[0] for n in nodes))}


def __prepare_title_in_modal(capture_uuid: str, title: str, from_popup: bool=False) -> dict[str, Markup]:
    span_title = Markup('<span class="d-inline-block text-break">{title}</span>').format(title=title)
    if from_popup:
        return {'display': Markup('<a href="#" class="openNewTab" data-capture="{capture_uuid}">{span_title}</a>').format(capture_uuid=capture_uuid, span_title=span_title),
                'filter': escape(title)}
    return {'display': Markup('<a href="{url}">{span_title}</a>').format(url=url_for("tree", tree_uuid=capture_uuid), span_title=span_title),
            'filter': escape(title)}


def __prepare_landings_in_modal(landing_page: str) -> dict[str, Markup]:
    return {'display': shorten_string(landing_page),
            'filter': escape(landing_page)}


def _safe_capture_title(capture_uuid: str, title: str, nodes: Sequence[tuple[str, str] | tuple[str, str, str | None]], from_popup: bool) -> dict[str, Markup]:
    title_modal = __prepare_title_in_modal(capture_uuid, title, from_popup)
    node_view = __prepare_node_view(capture_uuid, nodes, from_popup)
    # NOTE: This one is safe, as the values are already safe
    return {'display': Markup(f'{title_modal["display"]}</br>{node_view["display"]}'),
            'filter': Markup(f'{title_modal["filter"]} {node_view["filter"]}')}


index_link_template = app.jinja_env.from_string(source='''
<b>Page title</b>: <span title="{{title}}">{{title}}</span><br>
<b>Initial URL</b>: {{shorten_string(url)}}<br>
<a style="float: right;" href="{{url_for('tree', tree_uuid=capture_uuid)}}" class="btn btn-outline-primary" role="button">Show capture</a>
''')

redir_chain_template = app.jinja_env.from_string(source='''
{% from 'bootstrap5/utils.html' import render_icon %}

<div class="text-center">
 <div class="row"><div class="col">{{shorten_string(redirects[0])}}</div></div>
 {% for r in redirects[1:] %}
   <div class="row"><div class="col">{{ render_icon("arrow-down") }}</div></div>
   <div class="row"><div class="col">{{ shorten_string(r) }}</div></div>
 {% endfor %}
</div>
<a style="float: right;" href="{{url_for('redirects', tree_uuid=uuid)}}" class="btn btn-outline-primary" role="button">Download redirects</a>
''')


favicon_download_button_template = app.jinja_env.from_string(source='''
{% from 'bootstrap5/utils.html' import render_icon %}
<button type="button" class="btn btn-light downloadFaviconButton" data-mimetype="{{mimetype}}" data-b64favicon="{{b64_favicon}}" data-filename="favicon.ico">
  {{render_icon("cloud-download", title="Download the favicon")}}
</button>''')


def get_index(offset: int, limit: int, public: bool=True, show_error: bool=False, category: str | None=None,
              search: str | None=None) -> tuple[int, int | None, list[tuple[str, str, list[str], datetime]]]:
    '''Returns the index.'''
    total_filtered: int | None = None
    if category:
        # NOTE: 2026-01-05: when we search for categories, we want to also display the non-cached captures, even if it takes some time.
        total = get_indexing(flask_login.current_user).get_captures_category_count(category)
        if search:
            # get all the *recent* captures in that category, then filter
            cached_captures = [capture for capture in lookyloo.sorted_capture_cache(
                [uuid for uuid in get_indexing(flask_login.current_user).get_captures_category(category)],
                public=public,
                cached_captures_only=False) if capture.search(search)]
            total_filtered = len(cached_captures)
            cached_captures = cached_captures[offset: offset + limit]
        else:
            # get the subset of captures in that category only (faster)
            cached_captures = lookyloo.sorted_capture_cache(
                get_indexing(flask_login.current_user).get_captures_category(category,
                                                                             offset=offset,
                                                                             limit=limit),
                public=public,
                cached_captures_only=False)
    else:
        cut_time: datetime | None = None
        if time_delta_on_index:
            # We want to filter the captures on the index
            cut_time = (datetime.now() - timedelta(**time_delta_on_index))
        cached_captures = lookyloo.sorted_capture_cache(public=public, cached_captures_only=True, index_cut_time=cut_time)
        if not show_error:
            cached_captures = [cached for cached in cached_captures if not cached.error]
        total = len(cached_captures)

        if search:
            cached_captures = [capture for capture in cached_captures if capture.search(search)]
            total_filtered = len(cached_captures)
        cached_captures = cached_captures[offset: offset + limit]
    return total, total_filtered, [(cache.uuid, cache.title, cache.redirects, cache.timestamp) for cache in cached_captures]


@app.route('/tables/<string:table_name>/', methods=['POST'])
@app.route('/tables/<string:table_name>/<string:value>', methods=['POST'])
def post_table(table_name: str, value: str='') -> Response:
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search = request.form.get('search[value]', type=str)
    captures: list[tuple[str, str, datetime, str, str]] | list[tuple[str, str, str, datetime, list[tuple[str, str]]]] | list[tuple[str, str, str, datetime]] | list[tuple[str, str, list[str], datetime]]
    to_append: dict[str, int | str | dict[str, str] | dict[str, Markup]]
    if table_name == 'indexTable':
        show_error, category = get_index_params(request)
        show_hidden = (value == "hidden")
        if show_hidden and not flask_login.current_user.is_authenticated:
            # NOTE: hidden captures are only available to authenticated users.
            return jsonify({'error': 'Not allowed.'})

        if start is None or length is None:
            logger.warning(f'Missing start {start} or length {length}.')
            return jsonify({'error': f'Missing start {start} or length {length}.'})

        total, total_filtered, captures = get_index(public=show_hidden is False, category=category, offset=start, limit=length, search=search)
        prepared_captures = []
        for capture_uuid, title, redirects, capture_time in captures:
            to_append = {
                'page': {'display': render_template(index_link_template,
                                                    title=title,
                                                    url=redirects[0],
                                                    capture_uuid=capture_uuid),
                         'filter': escape(title)},
                'capture_time': capture_time.isoformat(),
            }
            to_append['redirects'] = {'display': Markup('No redirect'), 'filter': escape('')}
            if redirects:
                to_append['redirects'] = {'display': render_template(redir_chain_template,
                                                                     redirects=redirects,
                                                                     uuid=capture_uuid),
                                          'filter': escape(' '.join(redirects))}
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'categoriesTable':
        prepared_captures = []
        for category in get_indexing(flask_login.current_user).categories:
            nb_captures = get_indexing(flask_login.current_user).get_captures_category_count(category)
            to_append = {
                'total_captures': nb_captures,
                'category': {'display': Markup('<a href="{url}">{category}</a>').format(url=url_for("index", category=category), category=category),
                             'filter': escape(category)}
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'HHHDetailsTable':
        hhh = value.strip()
        total, captures = get_hhh_investigator(hhh, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'cookieNameTable':
        cookie_name = value.strip()
        total, captures = get_cookie_name_investigator(cookie_name, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'bodyHashDetailsTable':
        body_hash = value.strip()
        total, captures = _get_body_hash_investigator(body_hash, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'identifierDetailsTable':
        identifier_type, identifier = value.strip().split('|')
        total, captures = get_identifier_investigator(identifier_type, identifier, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'capture_title': __prepare_title_in_modal(capture_uuid, title, from_popup),
                'landing_page': __prepare_landings_in_modal(landing_page)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'hashTypeDetailsTable':
        hash_type, h = value.strip().split('|')
        total, captures = get_capture_hash_investigator(hash_type, h, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'capture_title': __prepare_title_in_modal(capture_uuid, title, from_popup),
                'landing_page': __prepare_landings_in_modal(landing_page)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'faviconDetailsTable':
        total, captures = get_favicon_investigator(value.strip(), offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'capture_title': __prepare_title_in_modal(capture_uuid, title, from_popup),
                'landing_page': __prepare_landings_in_modal(landing_page)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'ipTable':
        total, captures = get_ip_investigator(value.strip(), offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'hostnameTable':
        total, captures = get_hostname_investigator(value.strip(), offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'tldTable':
        total, captures = get_tld_investigator(value.strip(), offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'domainTable':
        total, captures = get_domain_investigator(value.strip(), offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'urlTable':
        url = base64.urlsafe_b64decode(value.strip()).decode()
        total, captures = get_url_investigator(url, offset=start, limit=length, search=search)
        if search and start is not None and length is not None:
            total_filtered = len(captures)
            captures = captures[start:start + length]
        prepared_captures = []
        for capture_uuid, title, landing_page, capture_time, nodes in captures:
            to_append = {
                'capture_time': capture_time.isoformat(),
                'landing_page': __prepare_landings_in_modal(landing_page),
                'capture_title': _safe_capture_title(capture_uuid, title, nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify({'draw': draw, 'recordsTotal': total, 'recordsFiltered': total if not search else total_filtered, 'data': prepared_captures})

    if table_name == 'urlsTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for url, _info in get_all_urls(tree_uuid).items():
            to_append = {
                'total_captures': _info['total_captures'],
                'url': details_modal_button(target_modal_id='#urlDetailsModal',
                                            data_remote=url_for('url_details', url=_info['quoted_url']),
                                            button_string=shorten_string(url),
                                            search=url)
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'identifiersTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for id_type, identifiers in get_indexing(flask_login.current_user).get_identifiers_capture(tree_uuid).items():
            for identifier in identifiers:
                nb_captures = get_indexing(flask_login.current_user).get_captures_identifier_count(id_type, identifier)
                to_append = {
                    'total_captures': nb_captures,
                    'identifier': details_modal_button(target_modal_id='#identifierDetailsModal',
                                                       data_remote=url_for('identifier_details', identifier_type=id_type, identifier=identifier),
                                                       button_string=shorten_string(identifier),
                                                       search=identifier),
                    'identifier_type': id_type
                }
                prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'hostnamesTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for _hostname, _info in get_all_hostnames(tree_uuid).items():
            h_nodes: list[tuple[str, str]] = [(node.name, node.uuid) for node in _info['nodes']]  # type: ignore[union-attr]
            to_append = {
                'total_captures': _info['total_captures'],
                'hostname': details_modal_button(target_modal_id='#hostnameDetailsModal',
                                                 data_remote=url_for('hostname_details', hostname=_hostname),
                                                 button_string=shorten_string(_hostname),
                                                 search=_hostname),
                'ip': details_modal_button(target_modal_id='#ipDetailsModal',
                                           data_remote=url_for('ip_details', ip=_info['ip']),
                                           button_string=shorten_string(_info['ip']),
                                           search=_info['ip']),  # type: ignore[arg-type]
                'urls': __prepare_node_view(tree_uuid, h_nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'treeHashesTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for hash_type, h in get_indexing(flask_login.current_user).get_hashes_types_capture(tree_uuid).items():
            to_append = {
                'total_captures': get_indexing(flask_login.current_user).get_captures_hash_type_count(hash_type, h),
                'capture_hash': details_modal_button(target_modal_id='#captureHashesTypesDetailsModal',
                                                     data_remote=url_for('capture_hash_details', hash_type=hash_type, h=h),
                                                     button_string=shorten_string(h),
                                                     search=h),
                'hash_type': hash_type
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'faviconsTable':
        tree_uuid = value.strip()
        prepared_captures = []
        success, favicons_zip = lookyloo.get_potential_favicons(tree_uuid, all_favicons=True, for_datauri=False)
        if not success:
            return jsonify({'error': 'No favicon found.'})
        with ZipFile(favicons_zip, 'r') as myzip:
            for name in myzip.namelist():
                if not name.endswith('.ico'):
                    continue
                favicon = myzip.read(name)
                if not favicon:
                    continue
                try:
                    mimetype = from_string(favicon, mime=True)
                except PureError:
                    # Not a valid image
                    continue
                favicon_sha512 = hashlib.sha512(favicon).hexdigest()
                b64_favicon = base64.b64encode(favicon).decode()
                to_append = {
                    'total_captures': get_indexing(flask_login.current_user).get_captures_favicon_count(favicon_sha512),
                    'favicon': details_modal_button(target_modal_id='#faviconDetailsModal', data_remote=url_for('favicon_detail', favicon_sha512=favicon_sha512),
                                                    button_string=Markup('<img src="data:{mimetype};base64,{b64_favicon}" style="width:32px;height:32px;" \
                                                                           title="Click to see other captures with the same favicon"/>').format(mimetype=mimetype, b64_favicon=b64_favicon),
                                                    search=favicon_sha512),
                    'shodan_mmh3': lookyloo.compute_mmh3_shodan(favicon),
                    'download': render_template(favicon_download_button_template, mimetype=mimetype, b64_favicon=b64_favicon)
                }

                prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'ipsTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for _ip, _info in get_all_ips(tree_uuid).items():
            if _ip.startswith('127'):
                # Skip the loopback entries
                continue
            ip_nodes: list[tuple[str, str]] = [(node.name, node.uuid) for node in _info['nodes']]
            to_append = {
                'total_captures': _info['total_captures'],
                'ip': details_modal_button(target_modal_id='#ipDetailsModal',
                                           data_remote=url_for('ip_details', ip=_ip),
                                           button_string=shorten_string(_ip),
                                           search=_ip),
                'hostname': details_modal_button(target_modal_id='#hostnameDetailsModal',
                                                 data_remote=url_for('hostname_details', hostname=_info['hostname']),
                                                 button_string=shorten_string(_info['hostname']),
                                                 search=_info['hostname']),
                'urls': __prepare_node_view(tree_uuid, ip_nodes, from_popup)
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == 'bodyHashesTable':
        tree_uuid = value.strip()
        prepared_captures = []
        for body_hash, _bh_info in get_all_body_hashes(tree_uuid).items():
            bh_nodes: list[tuple[str, str, str | None]] = [(node[0].name, node[0].uuid, '(embedded)' if node[1] else None) for node in _bh_info['nodes']]
            to_append = {
                'total_captures': _bh_info['total_captures'],
                'file_type': {'display': hash_icon_render(tree_uuid, _bh_info['nodes'][0][0].uuid,
                                                          _bh_info['mimetype'], body_hash),
                              'filter': escape(_bh_info['mimetype'])},
                'urls': __prepare_node_view(tree_uuid, bh_nodes, from_popup),
                'sha512': details_modal_button(target_modal_id='#bodyHashDetailsModal',
                                               data_remote=url_for('body_hash_details', body_hash=body_hash),
                                               button_string=shorten_string(body_hash),
                                               search=body_hash)
            }
            prepared_captures.append(to_append)
        return jsonify(prepared_captures)

    if table_name == "CIRCL_pdns_table":
        if not lookyloo.circl_pdns.available:
            return jsonify({'error': 'CIRCL PDNS is not available.'})
        query = value.strip()
        prepared_records = []
        if records := lookyloo.circl_pdns.get_passivedns(query, live=True if request.form.get('live') == 'true' else False):
            for record in records:
                if isinstance(record.rdata, list):
                    data = ', '.join(record.rdata)
                else:
                    data = record.rdata

                if record.rrtype in ['A', 'AAAA']:
                    # make the rrname a link to IP view
                    rrname_url = url_for('ip_details', ip=record.rrname, from_popup=True)
                    rrname = Markup('<a href="{url}">{rrname}</a>').format(url=rrname_url, rrname=record.rrname)
                else:
                    rrname = escape(record.rrname)

                to_append = {
                    'time_first': record.time_first_datetime.isoformat(),
                    'time_last': record.time_last_datetime.isoformat(),
                    'rrtype': record.rrtype,
                    'rdata': Markup('<span class="d-inline-block text-break">{}</span>').format(data),
                    'rrname': Markup('<span class="d-inline-block text-break">{}</span>').format(rrname)
                }
                prepared_records.append(to_append)
        return jsonify(prepared_records)

    return jsonify({})


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
