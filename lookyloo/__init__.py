#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import CrawledTree
from scrapysplashwrapper import crawl

from flask import Flask, render_template, request, session, send_file, redirect, url_for, Response
from flask_bootstrap import Bootstrap

from datetime import datetime

import pickle
import tempfile
import pathlib
import time

from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import base64
import os
from uuid import uuid4

from pysanejs import SaneJS

from .helpers import get_homedir, get_socket_path
from redis import Redis

app = Flask(__name__)


secret_file_path = get_homedir() / 'secret_key'

if not secret_file_path.exists() or secret_file_path.stat().st_size < 64:
    with secret_file_path.open('wb') as f:
        f.write(os.urandom(64))

with secret_file_path.open('rb') as f:
    app.config['SECRET_KEY'] = f.read()

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.debug = False

HAR_DIR = get_homedir() / 'scraped'
HAR_DIR.mkdir(parents=True, exist_ok=True)

SPLASH = 'http://127.0.0.1:8050'
SANE_JS = 'http://127.0.0.1:5007'

if SANE_JS:
    try:
        sanejs = SaneJS(SANE_JS)
        if sanejs.is_up:
            has_sane_js = True
        else:
            has_sane_js = False
    except Exception:
        has_sane_js = False

r = Redis(unix_socket_path=get_socket_path('cache'), decode_responses=True)


def get_report_dirs():
    # Cleanup HAR_DIR of failed runs.
    for report_dir in HAR_DIR.iterdir():
        if report_dir.is_dir() and not report_dir.iterdir():
            report_dir.rmdir()
        if not (report_dir / 'uuid').exists():
            # Create uuid if missing
            with (report_dir / 'uuid').open('w') as f:
                f.write(str(uuid4()))
    return sorted(HAR_DIR.iterdir(), reverse=True)


def get_lookup_dirs():
    # Build lookup table trees
    lookup_dirs = {}
    for report_dir in get_report_dirs():
        with (report_dir / 'uuid').open() as f:
            lookup_dirs[f.read().strip()] = report_dir
    return lookup_dirs


def cleanup_old_tmpfiles():
    for tmpfile in pathlib.Path(tempfile.gettempdir()).glob('lookyloo*'):
        if time.time() - tmpfile.stat().st_atime > 36000:
            tmpfile.unlink()


def load_image(report_dir):
    with open(list(report_dir.glob('*.png'))[0], 'rb') as f:
        return BytesIO(f.read())


def load_tree(report_dir):
    session.clear()
    har_files = sorted(report_dir.glob('*.har'))
    ct = CrawledTree(har_files)
    ct.find_parents()
    ct.join_trees()
    temp = tempfile.NamedTemporaryFile(prefix='lookyloo', delete=False)
    pickle.dump(ct, temp)
    temp.close()
    session["tree"] = temp.name
    return ct.to_json(), ct.start_time.isoformat(), ct.user_agent, ct.root_url


def sane_js_query(sha512: str):
    if has_sane_js:
        return sanejs.sha512(sha512)
    return {'response': []}


def scrape(url, depth: int=1, user_agent: str=None, perma_uuid: str=None):
    if not url.startswith('http'):
        url = f'http://{url}'
    items = crawl(SPLASH, url, depth, user_agent=user_agent, log_enabled=True, log_level='INFO')
    if not items:
        # broken
        pass
    if not perma_uuid:
        perma_uuid = str(uuid4())
    width = len(str(len(items)))
    dirpath = HAR_DIR / datetime.now().isoformat()
    dirpath.mkdir()
    for i, item in enumerate(items):
        harfile = item['har']
        png = base64.b64decode(item['png'])
        child_frames = item['childFrames']
        html = item['html']
        with (dirpath / '{0:0{width}}.har'.format(i, width=width)).open('w') as f:
            json.dump(harfile, f)
        with (dirpath / '{0:0{width}}.png'.format(i, width=width)).open('wb') as f:
            f.write(png)
        with (dirpath / '{0:0{width}}.html'.format(i, width=width)).open('w') as f:
            f.write(html)
        with (dirpath / '{0:0{width}}.frames.json'.format(i, width=width)).open('w') as f:
            json.dump(child_frames, f)
        with (dirpath / 'uuid').open('w') as f:
            f.write(perma_uuid)
    return perma_uuid


@app.route('/submit', methods=['POST', 'GET'])
def submit():
    to_query = request.get_json(force=True)
    perma_uuid = str(uuid4())
    p = r.pipeline()
    p.hmset(perma_uuid, to_query)
    p.sadd('to_scrape', perma_uuid)
    p.execute()
    return Response(perma_uuid, mimetype='text/text')


@app.route('/scrape', methods=['GET', 'POST'])
def scrape_web():
    if request.form.get('url'):
        perma_uuid = scrape(request.form.get('url'), request.form.get('depth'))
        return redirect(url_for('tree', tree_uuid=perma_uuid))
    return render_template('scrape.html')


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
            sane_js_r = sane_js_query(url.body_hash)
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


@app.route('/tree/<string:tree_uuid>/image', methods=['GET'])
def image(tree_uuid):
    lookup_dirs = get_lookup_dirs()
    report_dir = lookup_dirs[tree_uuid]
    to_return = load_image(report_dir)
    return send_file(to_return, mimetype='image/png',
                     as_attachment=True, attachment_filename='image.png')


@app.route('/tree/<string:tree_uuid>', methods=['GET'])
def tree(tree_uuid):
    lookup_dirs = get_lookup_dirs()
    report_dir = lookup_dirs[tree_uuid]
    tree_json, start_time, user_agent, root_url = load_tree(report_dir)
    return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                           user_agent=user_agent, root_url=root_url, tree_uuid=tree_uuid)


@app.route('/', methods=['GET'])
def index():
    if request.method == 'HEAD':
        # Just returns ack if the webserver is running
        return 'Ack'
    cleanup_old_tmpfiles()
    session.clear()
    titles = []
    if not HAR_DIR.exists():
        HAR_DIR.mkdir(parents=True)
    for report_dir in get_report_dirs():
        har_files = sorted(report_dir.glob('*.har'))
        if not har_files:
            continue
        with har_files[0].open() as f:
            j = json.load(f)
            title = j['log']['pages'][0]['title']
        with (report_dir / 'uuid').open() as f:
            uuid = f.read().strip()
        titles.append((uuid, title))

    return render_template('index.html', titles=titles)


if __name__ == '__main__':
    app.run(port=5001, threaded=True)
