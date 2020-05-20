#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import os
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, render_template, request, send_file, redirect, url_for, Response, flash
from flask_bootstrap import Bootstrap  # type: ignore
from flask_httpauth import HTTPDigestAuth  # type: ignore

from lookyloo.helpers import get_homedir, update_user_agents, get_user_agents
from lookyloo.lookyloo import Lookyloo
from lookyloo.exceptions import NoValidHarFile
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

logging.basicConfig(level=lookyloo.get_config('loglevel'))


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
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if capture_dir:
        lookyloo.remove_pickle(capture_dir)
        return redirect(url_for('tree', tree_uuid=tree_uuid))
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
                                         os=request.form.get('os'), browser=request.form.get('browser'))
            return redirect(url_for('tree', tree_uuid=perma_uuid))
    user_agents = get_user_agents()
    user_agents.pop('by_frequency')
    return render_template('scrape.html', user_agents=user_agents)


@app.route('/tree/<string:tree_uuid>/hostname/<string:node_uuid>/text', methods=['GET'])
def hostnode_details_text(tree_uuid: str, node_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    hostnode = lookyloo.get_hostnode_from_tree(capture_dir, node_uuid)
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
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    hostnode = lookyloo.get_hostnode_from_tree(capture_dir, node_uuid)
    table_keys = {
        'js': "/static/javascript.png",
        'exe': "/static/exe.png",
        'css': "/static/css.png",
        'font': "/static/font.png",
        'html': "/static/html.png",
        'json': "/static/json.png",
        'iframe': "/static/ifr.png",
        'image': "/static/img.png",
        'unknown_mimetype': "/static/wtf.png",
        'video': "/static/video.png",
        'request_cookie': "/static/cookie_read.png",
        'response_cookie': "/static/cookie_received.png",
        'redirect': "/static/redirect.png",
        'redirect_to_nothing': "/static/cookie_in_url.png"
    }

    urls = []
    if lookyloo.sanejs.available:
        to_lookup = [url.body_hash for url in hostnode.urls if hasattr(url, 'body_hash')]
        lookups = lookyloo.sanejs.hashes_lookup(to_lookup)
    for url in hostnode.urls:
        if lookyloo.sanejs.available and hasattr(url, 'body_hash') and url.body_hash in lookups:
            url.add_feature('sane_js_details', lookups[url.body_hash])
            if lookups[url.body_hash] and isinstance(lookups[url.body_hash], list):
                url.add_feature('sane_js_details_to_print', f'{" ".join(lookups[url.body_hash][0].split("|"))} and {len(lookups[url.body_hash])-1} other files')
        urls.append(url)
    return render_template('hostname_popup.html',
                           tree_uuid=tree_uuid,
                           hostname_uuid=node_uuid,
                           hostname=hostnode.name,
                           urls=urls,
                           keys=table_keys)


@app.route('/tree/<string:tree_uuid>/url/<string:node_uuid>', methods=['GET'])
def urlnode_details(tree_uuid: str, node_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    urlnode = lookyloo.get_urlnode_from_tree(capture_dir, node_uuid)
    to_return = BytesIO()
    got_content = False
    if hasattr(urlnode, 'body'):
        body_content = urlnode.body.getvalue()
        if body_content:
            got_content = True
            with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
                zfile.writestr(urlnode.filename, urlnode.body.getvalue())
    if not got_content:
        with ZipFile(to_return, 'w', ZIP_DEFLATED) as zfile:
            zfile.writestr('file.txt', b'Response body empty')
    to_return.seek(0)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='file.zip')


@app.route('/tree/<string:tree_uuid>/trigger_modules/', defaults={'force': False})
@app.route('/tree/<string:tree_uuid>/trigger_modules/<int:force>', methods=['GET'])
def trigger_modules(tree_uuid: str, force: int):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    lookyloo.trigger_modules(capture_dir, True if force else False)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/stats', methods=['GET'])
def stats(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    stats = lookyloo.get_statistics(capture_dir)
    return render_template('statistics.html', uuid=tree_uuid, stats=stats)


@app.route('/tree/<string:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    modules_responses = lookyloo.get_modules_responses(capture_dir)
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

    return render_template('modules.html', uuid=tree_uuid, vt=vt_short_result)


@app.route('/tree/<string:tree_uuid>/image', methods=['GET'])
def image(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    to_return = lookyloo.get_screenshot(capture_dir)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, attachment_filename='image.png')


@app.route('/tree/<string:tree_uuid>/html', methods=['GET'])
def html(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    to_return = lookyloo.get_html(capture_dir)
    return send_file(to_return, mimetype='text/html',
                     as_attachment=True, attachment_filename='page.html')


@app.route('/tree/<string:tree_uuid>/export', methods=['GET'])
def export(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    to_return = lookyloo.get_capture(capture_dir)
    return send_file(to_return, mimetype='application/zip',
                     as_attachment=True, attachment_filename='capture.zip')


@app.route('/redirects/<string:tree_uuid>', methods=['GET'])
def redirects(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    cache = lookyloo.capture_cache(capture_dir)
    if not cache:
        return Response('Not available.', mimetype='text/text')
    if not cache['redirects']:
        return Response('No redirects.', mimetype='text/text')
    to_return = BytesIO('\n'.join(cache['redirects']).encode())
    return send_file(to_return, mimetype='text/text',
                     as_attachment=True, attachment_filename='redirects.txt')


@app.route('/cache_tree/<string:tree_uuid>', methods=['GET'])
def cache_tree(tree_uuid: str):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if capture_dir:
        lookyloo.load_tree(capture_dir)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>/send_mail', methods=['POST', 'GET'])
def send_mail(tree_uuid: str):
    comment: str = request.form.get('comment') if request.form.get('comment') else ''  # type: ignore
    lookyloo.send_mail(tree_uuid, comment)
    return redirect(url_for('tree', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
def tree(tree_uuid: str):
    if tree_uuid == 'False':
        flash("Unable to process your request. The domain may not exist, or splash isn't started", 'error')
        return redirect(url_for('index'))
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        flash(f'Unable to find this UUID ({tree_uuid}). The capture may still be ongoing, try again later.', 'error')
        return redirect(url_for('index'))

    cache = lookyloo.capture_cache(capture_dir)
    if not cache:
        flash(f'Invalid cache.', 'error')
        return redirect(url_for('index'))

    if 'error' in cache:
        flash(cache['error'], 'error')
        return redirect(url_for('index'))

    try:
        if lookyloo.get_config('enable_mail_notification'):
            enable_mail_notification = True
        else:
            enable_mail_notification = False
        tree_json, start_time, user_agent, root_url, meta = lookyloo.load_tree(capture_dir)
        return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                               user_agent=user_agent, root_url=root_url, tree_uuid=tree_uuid,
                               meta=meta, enable_mail_notification=enable_mail_notification)
    except NoValidHarFile as e:
        return render_template('error.html', error_message=e)


def index_generic(show_hidden: bool=False):
    titles = []
    if time_delta_on_index:
        # We want to filter the captures on the index
        cut_time = datetime.now() - timedelta(**time_delta_on_index)
    else:
        cut_time = None  # type: ignore
    for capture_dir in lookyloo.capture_dirs:
        cached = lookyloo.capture_cache(capture_dir)
        if not cached or 'error' in cached:
            continue
        if show_hidden:
            if 'no_index' not in cached:
                # Only display the hidden ones
                continue
        elif 'no_index' in cached:
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
