#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pickle
from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import os
from pathlib import Path

from flask import Flask, render_template, request, session, send_file, redirect, url_for, Response, flash
from flask_bootstrap import Bootstrap  # type: ignore
from flask_httpauth import HTTPDigestAuth  # type: ignore

from lookyloo.helpers import get_homedir, update_user_agents, get_user_agents
from lookyloo.lookyloo import Lookyloo
from lookyloo.exceptions import NoValidHarFile

from typing import Tuple

import logging

app: Flask = Flask(__name__)

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

logging.basicConfig(level=lookyloo.get_config('loglevel'))


@auth.get_password
def get_pw(username):
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


@app.route('/tree/<tree_uuid>/rebuild')
@auth.login_required
def rebuild_tree(tree_uuid):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if capture_dir:
        lookyloo.remove_pickle(capture_dir)
        return redirect(url_for('tree', tree_uuid=tree_uuid))
    return redirect(url_for('index'))


# keep
def load_tree(capture_dir: Path) -> Tuple[dict, str, str, str, dict]:
    session.clear()
    temp_file_name, tree_json, tree_time, tree_ua, tree_root_url, meta = lookyloo.load_tree(capture_dir)
    session["tree"] = temp_file_name
    return tree_json, tree_time, tree_ua, tree_root_url, meta


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
        perma_uuid = lookyloo.scrape(url=request.form.get('url'),
                                     cookies_pseudofile=cookie_file,
                                     depth=request.form.get('depth'),
                                     listing=request.form.get('listing'), user_agent=request.form.get('user_agent'),
                                     os=request.form.get('os'), browser=request.form.get('browser'))
        return redirect(url_for('tree', tree_uuid=perma_uuid))
    user_agents = get_user_agents()
    user_agents.pop('by_frequency')
    return render_template('scrape.html', user_agents=user_agents)


@app.route('/tree/hostname/<node_uuid>/text', methods=['GET'])
def hostnode_details_text(node_uuid):
    with open(session["tree"], 'rb') as f:
        ct = pickle.load(f)
    hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
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


@app.route('/tree/hostname/<node_uuid>', methods=['GET'])
def hostnode_details(node_uuid):
    with open(session["tree"], 'rb') as f:
        ct = pickle.load(f)
    hostnode = ct.root_hartree.get_host_node_by_uuid(node_uuid)
    urls = []
    for url in hostnode.urls:
        if hasattr(url, 'body_hash'):
            sane_js_r = lookyloo.sane_js_query(url.body_hash)
            if sane_js_r.get('response'):
                url.add_feature('sane_js_details', sane_js_r['response'])
                print('######## SANEJS ##### ', url.sane_js_details)
        urls.append(url.to_json())
    return json.dumps(urls)


@app.route('/tree/url/<node_uuid>', methods=['GET'])
def urlnode_details(node_uuid):
    with open(session["tree"], 'rb') as f:
        ct = pickle.load(f)
    urlnode = ct.root_hartree.get_url_node_by_uuid(node_uuid)
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
def trigger_modules(tree_uuid, force):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    lookyloo.trigger_modules(capture_dir, force)
    return redirect(url_for('modules', tree_uuid=tree_uuid))


@app.route('/tree/<string:tree_uuid>/modules', methods=['GET'])
def modules(tree_uuid):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    modules_responses = lookyloo.get_modules_responses(capture_dir)
    if not modules_responses:
        return redirect(url_for('tree', tree_uuid=tree_uuid))

    vt_short_result = {}
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
def image(tree_uuid):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    to_return = lookyloo.load_image(capture_dir)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, attachment_filename='image.png')


@app.route('/redirects/<string:tree_uuid>', methods=['GET'])
def redirects(tree_uuid):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        return Response('Not available.', mimetype='text/text')
    cache = lookyloo.capture_cache(capture_dir)
    if not cache['redirects']:
        return Response('No redirects.', mimetype='text/text')
    to_return = BytesIO('\n'.join(cache['redirects']).encode())
    return send_file(to_return, mimetype='text/text',
                     as_attachment=True, attachment_filename='redirects.txt')


@app.route('/cache_tree/<string:tree_uuid>', methods=['GET'])
def cache_tree(tree_uuid):
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if capture_dir:
        lookyloo.load_tree(capture_dir)
    return redirect(url_for('index'))


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
def tree(tree_uuid):
    if tree_uuid == 'False':
        flash("Unable to process your request. The domain may not exist, or splash isn't started", 'error')
        return redirect(url_for('index'))
    capture_dir = lookyloo.lookup_capture_dir(tree_uuid)
    if not capture_dir:
        flash(f'Unable to find this UUID ({tree_uuid}). The capture may still be ongoing, try again later.', 'error')
        return redirect(url_for('index'))

    cache = lookyloo.capture_cache(capture_dir)
    if 'error' in cache:
        flash(cache['error'], 'error')
        return redirect(url_for('index'))

    try:
        tree_json, start_time, user_agent, root_url, meta = load_tree(capture_dir)
        return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                               user_agent=user_agent, root_url=root_url, tree_uuid=tree_uuid,
                               meta=meta)
    except NoValidHarFile as e:
        return render_template('error.html', error_message=e)


@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    lookyloo.cleanup_old_tmpfiles()
    update_user_agents()
    titles = []
    for capture_dir in lookyloo.capture_dirs:
        cached = lookyloo.capture_cache(capture_dir)
        if not cached or 'no_index' in cached or 'error' in cached:
            continue
        titles.append((cached['uuid'], cached['title'], cached['timestamp'], cached['url'],
                       cached['redirects'], True if cached['incomplete_redirects'] == '1' else False))
    titles = sorted(titles, key=lambda x: (x[2], x[3]), reverse=True)
    return render_template('index.html', titles=titles)
