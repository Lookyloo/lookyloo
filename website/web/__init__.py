#!/usr/bin/env python3

import calendar
import http
import json
import logging
import logging.config
import os
import time

import filetype  # type: ignore

from datetime import date, datetime, timedelta, timezone
from importlib.metadata import version
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Union, TypedDict
from urllib.parse import quote_plus, unquote_plus, urlparse
from uuid import uuid4
from zipfile import ZipFile

import flask_login  # type: ignore
from flask import (Flask, Response, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)
from flask_bootstrap import Bootstrap5  # type: ignore
from flask_cors import CORS  # type: ignore
from flask_restx import Api  # type: ignore
from lacuscore import CaptureStatus
from pymisp import MISPEvent, MISPServerError
from werkzeug.security import check_password_hash

from lookyloo.default import get_config
from lookyloo.exceptions import MissingUUID, NoValidHarFile
from lookyloo.helpers import get_taxonomies, UserAgents, load_cookies
from lookyloo.lookyloo import Indexing, Lookyloo

from .genericapi import api as generic_api
from .helpers import (User, build_users_table, get_secret_key,
                      load_user_from_request, src_request_ip, sri_load)
from .proxied import ReverseProxied

logging.config.dictConfig(get_config('logging'))

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

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


@login_manager.user_loader
def user_loader(username):
    if username not in build_users_table():
        return None
    user = User()
    user.id = username
    return user


@login_manager.request_loader
def _load_user_from_request(request):
    return load_user_from_request(request)


@app.route('/login', methods=['GET', 'POST'])
def login():
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
@flask_login.login_required
def logout():
    flask_login.logout_user()
    flash('Successfully logged out.', 'success')
    return redirect(url_for('index'))


# Config

lookyloo: Lookyloo = Lookyloo()

time_delta_on_index = get_config('generic', 'time_delta_on_index')
blur_screenshot = get_config('generic', 'enable_default_blur_screenshot')

use_own_ua = get_config('generic', 'use_user_agents_users')
enable_mail_notification = get_config('generic', 'enable_mail_notification')
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
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return ("{:.1f}{}{}".format(num, 'Yi', suffix)).strip()


app.jinja_env.globals.update(sizeof_fmt=sizeof_fmt)


def http_status_description(code: int):
    if code in http.client.responses:
        return http.client.responses[code]
    return f'Invalid code: {code}'


app.jinja_env.globals.update(http_status_description=http_status_description)


def month_name(month: int):
    return calendar.month_name[month]


app.jinja_env.globals.update(month_name=month_name)


def get_sri(directory: str, filename: str) -> str:
    sha512 = sri_load()[directory][filename]
    return f'sha512-{sha512}'


app.jinja_env.globals.update(get_sri=get_sri)


class Icon(TypedDict):
    icon: str
    tooltip: str


def get_icon(icon_id: str) -> Optional[Icon]:
    available_icons: Dict[str, Icon] = {
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


# ##### Generic/configuration methods #####

@app.after_request
def after_request(response):
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


# ##### Hostnode level methods #####

@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/hashes', methods=['GET'])
def hashes_hostnode(tree_uuid: str, node_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid, hostnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name=f'hashes.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>/text', methods=['GET'])
def urls_hostnode(tree_uuid: str, node_uuid: str):
    hostnode = lookyloo.get_hostnode_from_tree(tree_uuid, node_uuid)
    return send_file(BytesIO('\n'.join(url.name for url in hostnode.urls).encode()),
                     mimetype='test/plain', as_attachment=True, download_name=f'urls.{node_uuid}.txt')


@app.route('/tree/<string:tree_uuid>/host/<string:node_uuid>', methods=['GET'])
def hostnode_popup(tree_uuid: str, node_uuid: str):
    try:
        hostnode, urls = lookyloo.get_hostnode_investigator(tree_uuid, node_uuid)
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
def trigger_modules(tree_uuid: str):
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    auto_trigger = True if (request.args.get('auto_trigger') and request.args.get('auto_trigger') == 'True') else False
    lookyloo.trigger_modules(tree_uuid, force=force, auto_trigger=auto_trigger)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/historical_lookups', methods=['GET'])
def historical_lookups(tree_uuid: str):
    force = True if (request.args.get('force') and request.args.get('force') == 'True') else False
    data = lookyloo.get_historical_lookups(tree_uuid, force)
    return render_template('historical_lookups.html', tree_uuid=tree_uuid,
                           riskiq=data.get('riskiq'))


@app.route('/tree/<string:tree_uuid>/categories_capture/', defaults={'query': ''})
@app.route('/tree/<string:tree_uuid>/categories_capture/<string:query>', methods=['GET'])
def categories_capture(tree_uuid: str, query: str):
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
def uncategorize_capture(tree_uuid: str, category: str):
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.uncategorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully added to {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/categorize/', defaults={'category': ''})
@app.route('/tree/<string:tree_uuid>/categorize/<string:category>', methods=['GET'])
def categorize_capture(tree_uuid: str, category: str):
    if not enable_categorization:
        return jsonify({'response': 'Categorization not enabled.'})
    lookyloo.categorize_capture(tree_uuid, category)
    return jsonify({'response': f'{category} successfully removed from {tree_uuid}'})


@app.route('/tree/<string:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str):
    stats = lookyloo.get_statistics(tree_uuid)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


@app.route('/tree/<string:tree_uuid>/misp_lookup', methods=['GET'])
@flask_login.login_required
def web_misp_lookup_view(tree_uuid: str):
    hits = lookyloo.get_misp_occurrences(tree_uuid)
    if hits:
        misp_root_url = lookyloo.misp.client.root_url
    else:
        misp_root_url = ''
    return render_template('misp_lookup.html', uuid=tree_uuid, hits=hits, misp_root_url=misp_root_url)


@app.route('/tree/<string:tree_uuid>/misp_push', methods=['GET', 'POST'])
@flask_login.login_required
def web_misp_push_view(tree_uuid: str):
    error = False
    if not lookyloo.misp.available:
        flash('MISP module not available.', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    elif not lookyloo.misp.enable_push:
        flash('Push not enabled in MISP module.', 'error')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    else:
        event = lookyloo.misp_export(tree_uuid)
        if isinstance(event, dict):
            flash(f'Unable to generate the MISP export: {event}', 'error')
            return redirect(url_for('tree', tree_uuid=tree_uuid))

    if request.method == 'POST':
        # event is a MISPEvent at this point
        # Submit the event
        tags = request.form.getlist('tags')
        error = False
        events: List[MISPEvent] = []
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
            new_events = lookyloo.misp.push(events, True if request.form.get('force_push') else False,
                                            True if request.form.get('auto_publish') else False)
        except MISPServerError:
            flash(f'MISP returned an error, the event(s) might still have been created on {lookyloo.misp.client.root_url}', 'error')
        else:
            if isinstance(new_events, dict):
                flash(f'Unable to create event(s): {new_events}', 'error')
            else:
                for e in new_events:
                    flash(f'MISP event {e.id} created on {lookyloo.misp.client.root_url}', 'success')
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    else:
        # the 1st attribute in the event is the link to lookyloo
        existing_misp_url = lookyloo.misp.get_existing_event_url(event[-1].attributes[0].value)

    fav_tags = lookyloo.misp.get_fav_tags()
    cache = lookyloo.capture_cache(tree_uuid)

    return render_template('misp_push_view.html', tree_uuid=tree_uuid,
                           event=event[0], fav_tags=fav_tags,
                           existing_event=existing_misp_url,
                           auto_publish=lookyloo.misp.auto_publish,
                           has_parent=True if cache and cache.parent else False,
                           default_tags=lookyloo.misp.default_tags)


@app.route('/tree/<string:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid: str):
    modules_responses = lookyloo.get_modules_responses(tree_uuid)
    if not modules_responses:
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    vt_short_result: Dict[str, Dict[str, Any]] = {}
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

    pi_short_result: Dict[str, str] = {}
    if 'pi' in modules_responses:
        pi = modules_responses.pop('pi')
        for url, full_report in pi.items():
            if not full_report:
                continue
            pi_short_result[url] = full_report['results'][0]['tag_label']

    phishtank_short_result: Dict[str, Dict] = {'urls': {}, 'ips_hits': {}}
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

    urlhaus_short_result: Dict[str, List] = {'urls': []}
    if 'urlhaus' in modules_responses:
        # TODO: make a short result
        uh = modules_responses.pop('urlhaus')
        for url, results in uh['urls'].items():
            if results:
                urlhaus_short_result['urls'].append(results)

    urlscan_to_display: Dict = {}
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
def redirects(tree_uuid: str):
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
def image(tree_uuid: str):
    max_width = request.args.get('width')
    if max_width:
        to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, width=int(max_width))
    else:
        to_return = lookyloo.get_screenshot(tree_uuid)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, download_name='image.png')


@app.route('/tree/<string:tree_uuid>/data', methods=['GET'])
def data(tree_uuid: str):
    filename, data = lookyloo.get_data(tree_uuid)
    if len(filename) == 0:
        # TODO: return something saying it is not a valid request
        return

    if filetype.guess_mime(data.getvalue()) is None:
        mime = 'application/octet-stream'
    else:
        mime = filetype.guess_mime(data.getvalue())
    return send_file(data, mimetype=mime,
                     as_attachment=True, download_name=filename)


@app.route('/tree/<string:tree_uuid>/thumbnail/', defaults={'width': 64}, methods=['GET'])
@app.route('/tree/<string:tree_uuid>/thumbnail/<int:width>', methods=['GET'])
def thumbnail(tree_uuid: str, width: int):
    to_return = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=False, width=width)
    return send_file(to_return, mimetype='image/png')


@app.route('/tree/<string:tree_uuid>/html', methods=['GET'])
def html(tree_uuid: str):
    to_return = lookyloo.get_html(tree_uuid)
    return send_file(to_return, mimetype='text/html',
                     as_attachment=True, download_name='page.html')


@app.route('/tree/<string:tree_uuid>/cookies', methods=['GET'])
def cookies(tree_uuid: str):
    to_return = lookyloo.get_cookies(tree_uuid)
    return send_file(to_return, mimetype='application/json',
                     as_attachment=True, download_name='cookies.json')


@app.route('/tree/<string:tree_uuid>/hashes', methods=['GET'])
def hashes_tree(tree_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name='hashes.txt')


@app.route('/tree/<string:tree_uuid>/export', methods=['GET'])
def export(tree_uuid: str):
    to_return = lookyloo.get_capture(tree_uuid)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, download_name='capture.zip')


@app.route('/tree/<string:tree_uuid>/urls_rendered_page', methods=['GET'])
def urls_rendered_page(tree_uuid: str):
    urls = lookyloo.get_urls_rendered_page(tree_uuid)
    return render_template('urls_rendered.html', base_tree_uuid=tree_uuid, urls=urls)


@app.route('/tree/<string:tree_uuid>/hashlookup', methods=['GET'])
def hashlookup(tree_uuid: str):
    merged, total_ressources = lookyloo.merge_hashlookup_tree(tree_uuid)
    # We only want unique URLs for the template
    for sha1, entries in merged.items():
        entries['nodes'] = {node.name for node in entries['nodes']}
    return render_template('hashlookup.html', base_tree_uuid=tree_uuid, merged=merged, total_ressources=total_ressources)


@app.route('/bulk_captures/<string:base_tree_uuid>', methods=['POST'])
def bulk_captures(base_tree_uuid: str):
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
        capture = {'url': url,
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
@flask_login.login_required
def hide_capture(tree_uuid: str):
    lookyloo.hide_capture(tree_uuid)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/rebuild')
@flask_login.login_required
def rebuild_tree(tree_uuid: str):
    try:
        lookyloo.remove_pickle(tree_uuid)
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    except Exception:
        return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/cache', methods=['GET'])
def cache_tree(tree_uuid: str):
    lookyloo.capture_cache(tree_uuid)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/monitor', methods=['POST', 'GET'])
def monitor(tree_uuid: str):
    if not lookyloo.monitoring_enabled:
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    if request.form.get('name') or not request.form.get('confirm'):
        # got a bot.
        logging.info(f'{src_request_ip(request)} is a bot - {request.headers.get("User-Agent")}.')
        return redirect('https://www.youtube.com/watch?v=iwGFalTRHDA')

    collection: str = request.form['collection'] if request.form.get('collection') else ''
    frequency: str = request.form['frequency'] if request.form.get('frequency') else 'daily'
    cache = lookyloo.capture_cache(tree_uuid)
    monitoring_uuid = lookyloo.monitoring.monitor({'url': cache.url}, frequency=frequency, collection=collection)
    flash(f"Sent to monitoring: {monitoring_uuid}", 'success')
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str):
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
def tree(tree_uuid: str, node_uuid: Optional[str]=None):
    if tree_uuid == 'False':
        flash("Unable to process your request.", 'warning')
        return redirect(url_for('index'))
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

    try:
        ct = lookyloo.get_crawled_tree(tree_uuid)
        b64_thumbnail = lookyloo.get_screenshot_thumbnail(tree_uuid, for_datauri=True)
        screenshot_size = lookyloo.get_screenshot(tree_uuid).getbuffer().nbytes
        meta = lookyloo.get_meta(tree_uuid)
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
        return render_template('tree.html', tree_json=ct.to_json(),
                               info=cache,
                               tree_uuid=tree_uuid, public_domain=lookyloo.public_domain,
                               screenshot_thumbnail=b64_thumbnail, page_title=cache.title,
                               screenshot_size=screenshot_size,
                               meta=meta, enable_mail_notification=enable_mail_notification,
                               enable_monitoring=lookyloo.monitoring_enabled,
                               enable_context_by_users=enable_context_by_users,
                               enable_categorization=enable_categorization,
                               enable_bookmark=enable_bookmark,
                               misp_push=lookyloo.misp.available and lookyloo.misp.enable_push,
                               misp_lookup=lookyloo.misp.available and lookyloo.misp.enable_lookup,
                               blur_screenshot=blur_screenshot, urlnode_uuid=hostnode_to_highlight,
                               auto_trigger_modules=auto_trigger_modules,
                               confirm_message=confirm_message if confirm_message else 'Tick to confirm.',
                               parent_uuid=cache.parent,
                               has_redirects=True if cache.redirects else False)

    except NoValidHarFile:
        flash(f'Unable to build a tree for {tree_uuid}: {cache.error}.', 'warning')
        return index_generic()
    finally:
        lookyloo.update_tree_cache_info(os.getpid(), 'website')


@app.route('/tree/<string:tree_uuid>/mark_as_legitimate', methods=['POST'])
@flask_login.login_required
def mark_as_legitimate(tree_uuid: str):
    if request.data:
        legitimate_entries: Dict = request.get_json(force=True)
        lookyloo.add_to_legitimate(tree_uuid, **legitimate_entries)
    else:
        lookyloo.add_to_legitimate(tree_uuid)
    return jsonify({'message': 'Legitimate entry added.'})


@app.route('/tree/<string:tree_uuid>/body_hashes', methods=['GET'])
def tree_body_hashes(tree_uuid: str):
    body_hashes = lookyloo.get_all_body_hashes(tree_uuid)
    return render_template('tree_body_hashes.html', tree_uuid=tree_uuid, body_hashes=body_hashes)


@app.route('/tree/<string:tree_uuid>/pandora', methods=['GET'])
def pandora_submit(tree_uuid: str):
    filename, content = lookyloo.get_data(tree_uuid)
    response = lookyloo.pandora.submit_file(content, filename)
    return jsonify(response)


# ##### helpers #####

def index_generic(show_hidden: bool=False, show_error: bool=True, category: Optional[str]=None):
    titles = []
    cut_time: Optional[datetime] = None
    if time_delta_on_index:
        # We want to filter the captures on the index
        cut_time = (datetime.now() - timedelta(**time_delta_on_index)).replace(tzinfo=timezone.utc)

    for cached in lookyloo.sorted_capture_cache(index_cut_time=cut_time):
        if cut_time and cached.timestamp < cut_time:
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
                       cached.redirects, cached.incomplete_redirects))
    titles = sorted(titles, key=lambda x: (x[2], x[3]), reverse=True)
    return render_template('index.html', titles=titles, public_domain=lookyloo.public_domain,
                           show_project_page=get_config('generic', 'show_project_page'),
                           version=pkg_version)


def get_index_params(request):
    show_error: bool = True
    category: str = ''
    if hide_captures_with_error:
        show_error = True if (request.args.get('show_error') and request.args.get('show_error') == 'True') else False

    if enable_categorization:
        category = request.args['category'] if request.args.get('category') else ''
    return show_error, category


# ##### Index level methods #####

@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    show_error, category = get_index_params(request)
    return index_generic(show_error=show_error)


@app.route('/hidden', methods=['GET'])
@flask_login.login_required
def index_hidden():
    show_error, category = get_index_params(request)
    return index_generic(show_hidden=True, show_error=show_error, category=category)


@app.route('/cookies', methods=['GET'])
def cookies_lookup():
    i = Indexing()
    cookies_names = [(name, freq, i.cookies_names_number_domains(name)) for name, freq in i.cookies_names]
    return render_template('cookies.html', cookies_names=cookies_names)


@app.route('/ressources', methods=['GET'])
def ressources():
    i = Indexing()
    ressources = []
    for h, freq in i.ressources:
        domain_freq = i.ressources_number_domains(h)
        context = lookyloo.context.find_known_content(h)
        capture_uuid, url_uuid, hostnode_uuid = i.get_hash_uuids(h)
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
def categories():
    i = Indexing()
    return render_template('categories.html', categories=i.categories)


@app.route('/rebuild_all')
@flask_login.login_required
def rebuild_all():
    lookyloo.rebuild_all()
    return redirect(url_for('index'))


@app.route('/rebuild_cache')
@flask_login.login_required
def rebuild_cache():
    lookyloo.rebuild_cache()
    return redirect(url_for('index'))


@app.route('/search', methods=['GET', 'POST'])
def search():
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


def _prepare_capture_template(user_ua: Optional[str], predefined_url: Optional[str]=None):
    return render_template('capture.html', user_agents=user_agents.user_agents,
                           default=user_agents.default,
                           personal_ua=user_ua,
                           default_public=get_config('generic', 'default_public'),
                           devices=lookyloo.get_playwright_devices(),
                           predefined_url_to_capture=predefined_url if predefined_url else '')


@app.route('/recapture/<string:tree_uuid>', methods=['GET'])
def recapture(tree_uuid: str):
    cache = lookyloo.capture_cache(tree_uuid)
    if cache and hasattr(cache, 'url'):
        return _prepare_capture_template(user_ua=request.headers.get('User-Agent'),
                                         predefined_url=cache.url)
    flash(f'Unable to find the capture {tree_uuid} in the cache.', 'error')
    return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))


# ################## Submit existing capture ##################

@app.route('/submit_capture', methods=['GET', 'POST'])
def submit_capture():

    if request.method == 'POST':
        listing = True if request.form.get('listing') else False
        uuid = str(uuid4())  # NOTE: new UUID, because we do not want duplicates
        har: Optional[Dict[str, Any]] = None
        html: Optional[str] = None
        last_redirected_url: Optional[str] = None
        screenshot: Optional[bytes] = None
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
            cookies: Optional[List[Dict[str, str]]] = None
            has_error = False
            with ZipFile(BytesIO(request.files['full_capture'].stream.read()), 'r') as lookyloo_capture:
                for filename in lookyloo_capture.namelist():
                    if filename.endswith('0.har'):
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
                                       png=screenshot, html=html, cookies=cookies)
                return redirect(url_for('tree', tree_uuid=uuid))
        else:
            flash('Invalid submission: please submit at least an HAR file.', 'error')

    return render_template('submit_capture.html',
                           default_public=get_config('generic', 'default_public'),
                           public_domain=lookyloo.public_domain)


# #############################################################

@app.route('/capture', methods=['GET', 'POST'])
def capture_web():
    if flask_login.current_user.is_authenticated:
        user = flask_login.current_user.get_id()
    else:
        user = src_request_ip(request)

    if request.method == 'POST':
        if not (request.form.get('url') or request.form.get('urls') or 'document' in request.files):
            flash('Invalid submission: please submit at least a URL or a document.', 'error')
            return _prepare_capture_template(user_ua=request.headers.get('User-Agent'))

        capture_query: Dict[str, Union[str, bytes, int, bool]] = {}
        # check if the post request has the file part
        if 'cookies' in request.files and request.files['cookies'].filename:
            capture_query['cookies'] = request.files['cookies'].stream.read()

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

        if request.form.get('referer'):
            capture_query['referer'] = request.form['referer']

        if request.form.get('dnt'):
            capture_query['dnt'] = request.form['dnt']

        if request.form.get('headers'):
            capture_query['headers'] = request.form['headers']

        if request.form.get('proxy'):
            parsed_proxy = urlparse(request.form['proxy'])
            if parsed_proxy.scheme and parsed_proxy.hostname and parsed_proxy.port:
                if parsed_proxy.scheme in ['http', 'https', 'socks5']:
                    if (parsed_proxy.username and parsed_proxy.password) != (not parsed_proxy.username and not parsed_proxy.password):
                        capture_query['proxy'] = request.form['proxy']
                    else:
                        flash('You need to enter a username AND a password for your proxy.', 'error')
                else:
                    flash('Proxy scheme not supported: must be http(s) or socks5.', 'error')
            else:
                flash('Invalid proxy: Check that you entered a scheme, a hostname and a port.', 'error')

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
            capture_query['document'] = request.files['document'].stream.read()
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


@app.route('/cookies/<string:cookie_name>', methods=['GET'])
def cookies_name_detail(cookie_name: str):
    captures, domains = lookyloo.get_cookie_name_investigator(cookie_name.strip())
    return render_template('cookie_name.html', cookie_name=cookie_name, domains=domains, captures=captures)


@app.route('/body_hashes/<string:body_hash>', methods=['GET'])
def body_hash_details(body_hash: str):
    from_popup = True if (request.args.get('from_popup') and request.args.get('from_popup') == 'True') else False
    captures, domains = lookyloo.get_body_hash_investigator(body_hash.strip())
    return render_template('body_hash.html', body_hash=body_hash, domains=domains, captures=captures, from_popup=from_popup)


@app.route('/urls/<string:url>', methods=['GET'])
def url_details(url: str):
    url = unquote_plus(url).strip()
    hits = lookyloo.get_url_occurrences(url, limit=50)
    return render_template('url.html', url=url, hits=hits)


@app.route('/hostnames/<string:hostname>', methods=['GET'])
def hostname_details(hostname: str):
    hits = lookyloo.get_hostname_occurrences(hostname.strip(), with_urls_occurrences=True, limit=50)
    return render_template('hostname.html', hostname=hostname, hits=hits)


@app.route('/stats', methods=['GET'])
def statsfull():
    stats = lookyloo.get_stats()
    return render_template('stats.html', stats=stats)


@app.route('/whois/<string:query>', methods=['GET'])
@app.route('/whois/<string:query>/<int:email_only>', methods=['GET'])
def whois(query: str, email_only: int=0):
    to_return = lookyloo.uwhois.whois(query, bool(email_only))
    if isinstance(to_return, str):
        return send_file(BytesIO(to_return.encode()),
                         mimetype='test/plain', as_attachment=True, download_name=f'whois.{query}.txt')
    return jsonify(to_return)


# ##### Methods related to a specific URLNode #####

@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/request_cookies', methods=['GET'])
def urlnode_request_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.request_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.request_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, download_name='request_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/response_cookies', methods=['GET'])
def urlnode_response_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.response_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.response_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, download_name='response_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/urls_in_rendered_content', methods=['GET'])
def urlnode_urls_in_rendered_content(tree_uuid: str, node_uuid: str):
    # Note: we could simplify it with lookyloo.get_urls_rendered_page, but if at somepoint,
    # we have multiple page rendered on one tree, it will be a problem.
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not hasattr(urlnode, 'rendered_html') or not urlnode.rendered_html:
        return

    ct = lookyloo.get_crawled_tree(tree_uuid)
    not_loaded_urls = sorted(set(urlnode.urls_in_rendered_page)
                             - set(ct.root_hartree.all_url_requests.keys()))
    to_return = StringIO()
    to_return.writelines([f'{u}\n' for u in not_loaded_urls])
    return send_file(BytesIO(to_return.getvalue().encode()), mimetype='text/plain',
                     as_attachment=True, download_name='urls_in_rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/rendered_content', methods=['GET'])
def urlnode_rendered_content(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.rendered_html:
        return
    return send_file(BytesIO(urlnode.rendered_html.getvalue()), mimetype='text/plain',
                     as_attachment=True, download_name='rendered_content.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/posted_data', methods=['GET'])
def urlnode_post_request(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.posted_data:
        return
    posted: Union[str, bytes]
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
def get_ressource(tree_uuid: str, node_uuid: str):
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
def get_ressource_preview(tree_uuid: str, node_uuid: str, h_ressource: Optional[str]=None):
    ressource = lookyloo.get_ressource(tree_uuid, node_uuid, h_ressource)
    if not ressource:
        return Response('No preview available.', mimetype='text/text')
    filename, r, mimetype = ressource
    if mimetype.startswith('image'):
        return send_file(r, mimetype=mimetype,
                         as_attachment=True, download_name=filename)
    return Response('No preview available.', mimetype='text/text')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/hashes', methods=['GET'])
def hashes_urlnode(tree_uuid: str, node_uuid: str):
    hashes = lookyloo.get_hashes(tree_uuid, urlnode_uuid=node_uuid)
    return send_file(BytesIO('\n'.join(hashes).encode()),
                     mimetype='test/plain', as_attachment=True, download_name='hashes.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/add_context', methods=['POST'])
@flask_login.login_required
def add_context(tree_uuid: str, node_uuid: str):
    if not enable_context_by_users:
        return redirect(url_for('ressources'))

    context_data = request.form
    ressource_hash: str = context_data['hash_to_contextualize']
    hostnode_uuid: str = context_data['hostnode_uuid']
    callback_str: str = context_data['callback_str']
    legitimate: bool = True if context_data.get('legitimate') else False
    malicious: bool = True if context_data.get('malicious') else False
    details: Dict[str, Dict] = {'malicious': {}, 'legitimate': {}}
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
