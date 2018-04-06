#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import CrawledTree
from scrapysplashwrapper import crawl

from flask import Flask, render_template, request, session, send_file
from flask_bootstrap import Bootstrap

from datetime import datetime

import pickle
import tempfile
import pathlib
import time

from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import base64

app = Flask(__name__)

app.secret_key = 'changeme'

if app.secret_key == 'changeme':
    raise Exception('FFS, please set a proper secret key...')

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['SESSION_COOKIE_NAME'] = 'lookyloo'
app.debug = True

HAR_DIR = pathlib.Path('scraped')
SPLASH = 'http://127.0.0.1:8050'

HAR_DIR.mkdir(parents=True, exist_ok=True)


def cleanup_old_tmpfiles():
    for tmpfile in pathlib.Path(tempfile.gettempdir()).glob('lookyloo*'):
        if time.time() - tmpfile.stat().st_atime > 36000:
            tmpfile.unlink()


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


@app.route('/scrape', methods=['GET', 'POST'])
def scrape():
    if request.form.get('url'):
        url = request.form.get('url')
        if not url.startswith('http'):
            url = f'http://{url}'
        depth = request.form.get('depth')
        if depth is None:
            depth = 1
        items = crawl(SPLASH, url, depth, log_enabled=True, log_level='INFO')
        if not items:
            # broken
            pass
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
        return tree(0)
    return render_template('scrape.html')


def get_report_dirs():
    # Cleanup HAR_DIR of failed runs.
    for report_dir in HAR_DIR.iterdir():
        if report_dir.is_dir() and not report_dir.iterdir():
            report_dir.rmdir()
    return sorted(HAR_DIR.iterdir(), reverse=True)


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


@app.route('/tree/<int:tree_id>', methods=['GET'])
def tree(tree_id):
    report_dir = get_report_dirs()[tree_id]
    tree_json, start_time, user_agent, root_url = load_tree(report_dir)
    return render_template('tree.html', tree_json=tree_json, start_time=start_time,
                           user_agent=user_agent, root_url=root_url)


@app.route('/', methods=['GET'])
def index():
    cleanup_old_tmpfiles()
    session.clear()
    i = 0
    titles = []
    if not HAR_DIR.exists():
        HAR_DIR.mkdir(parents=True)
    for report_dir in get_report_dirs():
        har_files = sorted(report_dir.glob('*.har'))
        if not har_files:
            continue
        with open(har_files[0], 'r') as f:
            j = json.load(f)
            titles.append((i, j['log']['pages'][0]['title']))
        i += 1

    return render_template('index.html', titles=titles)


if __name__ == '__main__':
    app.run(port=5001, threaded=True)
