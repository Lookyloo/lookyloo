#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import os
from pathlib import Path
from datetime import datetime, timedelta
import json
import http

from flask import Flask, render_template, request, send_file, redirect, url_for, Response, flash, jsonify
from flask_bootstrap import Bootstrap  # type: ignore
from flask_httpauth import HTTPDigestAuth  # type: ignore

from lookyloo.helpers import get_homedir, update_user_agents, get_user_agents
from lookyloo.lookyloo import Lookyloo, Indexing
from lookyloo.exceptions import NoValidHarFile, MissingUUID
from .proxied import ReverseProxied

from typing import Optional, Dict, Any

import logging

app: Flask = Flask(__name__)
app.wsgi_app = ReverseProxied(app.wsgi_app)  # type: ignore

secret_file_path: Path = get_homedir() / 'secret_key'

if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
    with secret_file_path.open('wb') as f:
        f.write(os.urandom(64))

with secret_file_path.open('rb') as f:
    app.config['SECRET_KEY'] = f.read()

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.debug = False
auth = HTTPDigestAuth()

lookyloo: Lookyloo = Lookyloo()

user = lookyloo.get_config('cache_clean_user')
time_delta_on_index = lookyloo.get_config('time_delta_on_index')
blur_screenshot = lookyloo.get_config('enable_default_blur_screenshot')

logging.basicConfig(level=lookyloo.get_config('loglevel'))


# Method to make sizes in bytes human readable
# Source: https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


app.jinja_env.globals.update(sizeof_fmt=sizeof_fmt)


def http_status_description(code: int):
    if code in http.client.responses:
        return http.client.responses[code]
    return f'Invalid code: {code}'


app.jinja_env.globals.update(http_status_description=http_status_description)


@app.after_request
def after_request(response):
    ua = request.headers.get('User-Agent')
    real_ip = request.headers.get('X-Real-IP')
    if ua:
        if real_ip:
            lookyloo.cache_user_agents(ua, real_ip)
        else:
            lookyloo.cache_user_agents(ua, request.remote_addr)
    return response


@auth.get_password
def get_pw(username: str) -> Optional[str]:
    if username in user:
        return user.get(username)
    return None


@app.route('/rebuild_all')
@auth.login_required
def rebuild_all():
    lookyloo.rebuild_all()
    return redirect(url_for('index'))


@app.route('/rebuild_cache')
@auth.login_required
def rebuild_cache():
    lookyloo.rebuild_cache()
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/rebuild')
@auth.login_required
def rebuild_tree(tree_uuid: str):
    try:
        lookyloo.remove_pickle(tree_uuid)
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    except Exception:
        return redirect(url_for('index'))


@app.route('/submit', methods=['POST', 'GET'])
def submit():
    to_query = request.get_json(force=True)
    perma_uuid = lookyloo.enqueue_scrape(to_query)
    return Response(perma_uuid, mimetype='text/text')


@app.route('/scrape', methods=['GET', 'POST'])
def scrape_web():
    if request.form.get('url'):
        # check if the post request has the file part
        if 'cookies' in request.files and request.files['cookies'].filename:
            cookie_file = request.files['cookies'].stream
        else:
            cookie_file = None
        url = request.form.get('url')
        if url:
            depth: int = request.form.get('depth') if request.form.get('depth') else 1  # type: ignore
            listing: bool = request.form.get('listing') if request.form.get('listing') else False  # type: ignore
            perma_uuid = lookyloo.scrape(url=url, cookies_pseudofile=cookie_file,
                                         depth=depth, listing=listing,
                                         user_agent=request.form.get('user_agent'),
                                         referer=request.form.get('referer'),
                                         os=request.form.get('os'), browser=request.form.get('browser'))
            return redirect(url_for('tree', tree_uuid=perma_uuid))
    user_agents: Dict[str, Any] = {}
    if lookyloo.get_config('use_user_agents_users'):
        lookyloo.build_ua_file()
        # NOTE: For now, just generate the file, so we have an idea of the size
        # user_agents = get_user_agents('own_user_agents')
    if not user_agents:
        user_agents = get_user_agents()
    user_agents.pop('by_frequency')
    return render_template('scrape.html', user_agents=user_agents)


@app.route('/tree/<string:tree_uuid>/hostname/<string:node_uuid>/text', methods=['GET'])
def hostnode_details_text(tree_uuid: str, node_uuid: str):
    hostnode = lookyloo.get_hostnode_from_tree(tree_uuid, node_uuid)
    urls = []
    for url in hostnode.urls:
        urls.append(url.name)
    content = '''# URLs

{}
'''.format('\n'.join(urls))
    to_return = BytesIO(content.encode())
    to_return.seek(0)
    return send_file(to_return, mimetype='text/markdown',
                     as_attachment=True, attachment_filename='file.md')


@app.route('/tree/<string:tree_uuid>/hostname_popup/<string:node_uuid>', methods=['GET'])
def hostnode_popup(tree_uuid: str, node_uuid: str):
    keys_response = {
        'js': "/static/javascript.png",
        'exe': "/static/exe.png",
        'css': "/static/css.png",
        'font': "/static/font.png",
        'html': "/static/html.png",
        'json': "/static/json.png",
        'text': "/static/json.png",  # FIXME: Need new icon
        'iframe': "/static/ifr.png",
        'image': "/static/img.png",
        'unset_mimetype': "/static/wtf.png",
        'octet-stream': "/static/wtf.png",
        'unknown_mimetype': "/static/wtf.png",
        'video': "/static/video.png",
        'livestream': "/static/video.png",
        'response_cookie': "/static/cookie_received.png",
        # redirect has to be last
        'redirect': "/static/redirect.png",
        'redirect_to_nothing': "/static/cookie_in_url.png"
    }
    keys_request = {
        'request_cookie': "/static/cookie_read.png",
    }

    hostnode, urls = lookyloo.get_hostnode_investigator(tree_uuid, node_uuid)

    return render_template('hostname_popup.html',
                           tree_uuid=tree_uuid,
                           hostname_uuid=node_uuid,
                           hostname=hostnode.name,
                           urls=urls,
                           keys_response=keys_response,
                           keys_request=keys_request)


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/request_cookies', methods=['GET'])
def urlnode_request_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.request_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.request_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, attachment_filename='request_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/response_cookies', methods=['GET'])
def urlnode_response_cookies(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.response_cookie:
        return

    return send_file(BytesIO(json.dumps(urlnode.response_cookie, indent=2).encode()),
                     mimetype='text/plain', as_attachment=True, attachment_filename='response_cookies.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/posted_data', methods=['GET'])
def urlnode_post_request(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    if not urlnode.posted_data:
        return
    if isinstance(urlnode.posted_data, (dict, list)):
        # JSON blob, pretty print.
        posted = json.dumps(urlnode.posted_data, indent=2)
    else:
        posted = urlnode.posted_data

    if isinstance(posted, bytes):
        to_return = BytesIO(posted)
    else:
        to_return = BytesIO(posted.encode())
    to_return.seek(0)
    return send_file(to_return, mimetype='text/plain',
                     as_attachment=True, attachment_filename='posted_data.txt')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>/embedded_ressource', methods=['POST'])
def get_embedded_ressource(tree_uuid: str, node_uuid: str):
    url = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    h_request = request.form.get('ressource_hash')
    for mimetype, blobs in url.embedded_ressources.items():
        for h, blob in blobs:
            if h == h_request:
                to_return = BytesIO()
                with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
                    zfile.writestr('file.bin', blob.getvalue())
                to_return.seek(0)
                return send_file(to_return, mimetype='application/zip',
                                 as_attachment=True, attachment_filename='file.zip')


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>', methods=['GET'])
def urlnode_details(tree_uuid: str, node_uuid: str):
    urlnode = lookyloo.get_urlnode_from_tree(tree_uuid, node_uuid)
    to_return = BytesIO()
    got_content = False
    if hasattr(urlnode, 'body'):
        body_content = urlnode.body.getvalue()
        if body_content:
            got_content = True
            if hasattr(urlnode, 'json') and urlnode.json:
                try:
                    loaded = json.loads(body_content)
                    body_content = json.dumps(loaded, indent=2).encode()
                except Exception:
                    # Not json, but junk
                    pass
            with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
                zfile.writestr(urlnode.filename, body_content)
    if not got_content:
        with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
            zfile.writestr('file.txt', b'Response body empty')
    to_return.seek(0)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='file.zip')


@app.route('/tree/<string:tree_uuid>/trigger_modules/', defaults={'force': False})
@app.route('/tree/<string:tree_uuid>/trigger_modules/<int:force>', methods=['GET'])
def trigger_modules(tree_uuid: str, force: int):
    lookyloo.trigger_modules(tree_uuid, True if force else False)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str):
    stats = lookyloo.get_statistics(tree_uuid)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


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

    return render_template('modules.html', uuid=tree_uuid, vt=vt_short_result, pi=pi_short_result)


@app.route('/tree/<string:tree_uuid>/image', methods=['GET'])
def image(tree_uuid: str):
    to_return = lookyloo.get_screenshot(tree_uuid)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, attachment_filename='image.png')


@app.route('/tree/<string:tree_uuid>/html', methods=['GET'])
def html(tree_uuid: str):
    to_return = lookyloo.get_html(tree_uuid)
    return send_file(to_return, mimetype='text/html',
                     as_attachment=True, attachment_filename='page.html')


@app.route('/tree/<string:tree_uuid>/cookies', methods=['GET'])
def cookies(tree_uuid: str):
    to_return = lookyloo.get_cookies(tree_uuid)
    return send_file(to_return, mimetype='application/json',
                     as_attachment=True, attachment_filename='cookies.json')


@app.route('/tree/<string:tree_uuid>/export', methods=['GET'])
def export(tree_uuid: str):
    to_return = lookyloo.get_capture(tree_uuid)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='capture.zip')


@app.route('/tree/<string:tree_uuid>/hide', methods=['GET'])
@auth.login_required
def hide_capture(tree_uuid: str):
    lookyloo.hide_capture(tree_uuid)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/redirects/<string:tree_uuid>', methods=['GET'])
def redirects(tree_uuid: str):
    cache = lookyloo.capture_cache(tree_uuid)
    if not cache:
        return Response('Not available.', mimetype='text/text')
    if not cache['redirects']:
        return Response('No redirects.', mimetype='text/text')
    if cache['url'] == cache['redirects'][0]:
        to_return = BytesIO('\n'.join(cache['redirects']).encode())
    else:
        to_return = BytesIO('\n'.join([cache['url']] + cache['redirects']).encode())
    return send_file(to_return, mimetype='text/text',
                     as_attachment=True, attachment_filename='redirects.txt')


@app.route('/cache_tree/<string:tree_uuid>', methods=['GET'])
def cache_tree(tree_uuid: str):
    lookyloo.cache_tree(tree_uuid)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str):
    email: str = request.form.get('email') if request.form.get('email') else ''  # type: ignore
    if '@' not in email:
        # skip clearly incorrect emails
        email = ''
    comment: str = request.form.get('comment') if request.form.get('comment') else ''  # type: ignore
    lookyloo.send_mail(tree_uuid, email, comment)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
@app.route('/tree/<string:tree_uuid>/<string:urlnode_uuid>', methods=['GET'])
def tree(tree_uuid: str, urlnode_uuid: Optional[str]=None):
    if tree_uuid == 'False':
        flash("Unable to process your request. The domain may not exist, or splash isn't started", 'error')
        return redirect(url_for('index'))
    try:
        cache = lookyloo.capture_cache(tree_uuid)
    except MissingUUID:
        flash(f'Unable to find this UUID ({tree_uuid}). The capture may still be ongoing, try again later.', 'error')
        return redirect(url_for('index'))

    if not cache:
        flash('Invalid cache.', 'error')
        return redirect(url_for('index'))

    if 'error' in cache:
        flash(cache['error'], 'error')

    try:
        if lookyloo.get_config('enable_mail_notification'):
            enable_mail_notification = True
        else:
            enable_mail_notification = False
        tree_json, start_time, user_agent, root_url, meta = lookyloo.load_tree(tree_uuid)
        return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                               user_agent=user_agent, root_url=root_url, tree_uuid=tree_uuid,
                               meta=meta, enable_mail_notification=enable_mail_notification,
                               blur_screenshot=blur_screenshot,
                               urlnode_uuid=urlnode_uuid, has_redirects=True if cache['redirects'] else False)

    except NoValidHarFile as e:
        return render_template('error.html', error_message=e)


def index_generic(show_hidden: bool=False):
    titles = []
    if time_delta_on_index:
        # We want to filter the captures on the index
        cut_time = datetime.now() - timedelta(**time_delta_on_index)
    else:
        cut_time = None  # type: ignore
    for capture_uuid in lookyloo.capture_uuids:
        cached = lookyloo.capture_cache(capture_uuid)
        if not cached:
            continue
        if show_hidden:
            if 'no_index' not in cached:
                # Only display the hidden ones
                continue
        elif 'no_index' in cached:
            continue
        if 'timestamp' not in cached:
            # this is a buggy capture, skip
            continue
        if cut_time and datetime.fromisoformat(cached['timestamp'][:-1]) < cut_time:  # type: ignore
            continue
        titles.append((cached['uuid'], cached['title'], cached['timestamp'], cached['url'],
                       cached['redirects'], True if cached['incomplete_redirects'] == '1' else False))
    titles = sorted(titles, key=lambda x: (x[2], x[3]), reverse=True)
    return render_template('index.html', titles=titles)


@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    update_user_agents()
    return index_generic()


@app.route('/hidden', methods=['GET'])
@auth.login_required
def index_hidden():
    return index_generic(show_hidden=True)


@app.route('/cookies', methods=['GET'])
def cookies_lookup():
    i = Indexing()
    cookies_names = [(name, freq, i.cookies_names_number_domains(name)) for name, freq in i.cookies_names]
    return render_template('cookies.html', cookies_names=cookies_names)


@app.route('/cookies/<string:cookie_name>', methods=['GET'])
def cookies_name_detail(cookie_name: str):
    captures, domains = lookyloo.get_cookie_name_investigator(cookie_name)
    return render_template('cookie_name.html', cookie_name=cookie_name, domains=domains, captures=captures)


@app.route('/body_hashes/<string:body_hash>', methods=['GET'])
def body_hash_details(body_hash: str):
    captures, domains = lookyloo.get_body_hash_investigator(body_hash)
    return render_template('body_hash.html', body_hash=body_hash, domains=domains, captures=captures)


@app.route('/tree/<string:tree_uuid>/mark_as_legitimate', methods=['POST'])
def mark_as_legitimate(tree_uuid: str):
    if request.data:
        legitimate_entries = request.get_json(force=True)
        lookyloo.add_to_legitimate(tree_uuid, **legitimate_entries)
    else:
        lookyloo.add_to_legitimate(tree_uuid)
    return jsonify({'message': 'Legitimate entry added.'})


# Query API

@app.route('/json/<string:tree_uuid>/redirects', methods=['GET'])
def json_redirects(tree_uuid: str):
    cache = lookyloo.capture_cache(tree_uuid)
    if not cache:
        return {'error': 'UUID missing in cache, try again later.'}

    to_return: Dict[str, Any] = {'response': {'url': cache['url'], 'redirects': []}}
    if not cache['redirects']:
        to_return['response']['info'] = 'No redirects'
        return to_return
    if cache['incomplete_redirects']:
        # Trigger tree build, get all redirects
        lookyloo.load_tree(tree_uuid)
        cache = lookyloo.capture_cache(tree_uuid)
        if cache:
            to_return['response']['redirects'] = cache['redirects']
    else:
        to_return['response']['redirects'] = cache['redirects']

    return jsonify(to_return)
