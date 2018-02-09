#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from har2tree import CrawledTree
from scrapysplashwrapper import crawl

from flask import Flask, render_template, request, session, send_file
from flask_bootstrap import Bootstrap

from glob import glob
import os
from datetime import datetime

import pickle
import tempfile
import pathlib

from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO
import base64

app = Flask(__name__)

app.secret_key = 'changeme'

if app.secret_key == 'changeme':
    raise Exception('FFS, please set a proper secret key...')

Bootstrap(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.debug = True

HAR_DIR = 'scraped'
SPLASH = 'http://127.0.0.1:8050'

pathlib.Path(HAR_DIR).mkdir(parents=True, exist_ok=True)


@app.before_request
def session_management():
    # make the session last indefinitely until it is cleared
    session.permanent = True


def load_tree(report_dir):
    if session.get('tree'):
        # TODO delete file
        pass
    session.clear()
    har_files = sorted(glob(os.path.join(HAR_DIR, report_dir, '*.har')))
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
            url = 'http://{}'.format(url)
        depth = request.form.get('depth')
        if depth is None:
            depth = 1
        items = crawl(SPLASH, url, depth, log_enabled=True, log_level='INFO')
        if not items:
            # broken
            pass
        width = len(str(len(items)))
        dirpath = os.path.join(HAR_DIR, datetime.now().isoformat())
        os.makedirs(dirpath)
        for i, item in enumerate(items):
            harfile = item['har']
            png = base64.b64decode(item['png'])
            child_frames = item['childFrames']
            with open(os.path.join(dirpath, '{0:0{width}}.har'.format(i, width=width)), 'w') as f:
                json.dump(harfile, f)
            with open(os.path.join(dirpath, '{0:0{width}}.png'.format(i, width=width)), 'wb') as f:
                f.write(png)
            with open(os.path.join(dirpath, '{0:0{width}}.frames.json'.format(i, width=width)), 'w') as f:
                json.dump(child_frames, f)
        return tree(0)
    return render_template('scrape.html')


def get_report_dirs():
    # Cleanup HAR_DIR of failed runs.
    for report_dir in os.listdir(HAR_DIR):
        if not os.listdir(os.path.join(HAR_DIR, report_dir)):
            os.rmdir(os.path.join(HAR_DIR, report_dir))
    return sorted(os.listdir(HAR_DIR), reverse=True)


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
    if hasattr(urlnode, 'body'):
        with ZipFile(to_return, 'a', ZIP_DEFLATED, False) as zfile:
            zfile.writestr(urlnode.filename, urlnode.body.getvalue())
        to_return.seek(0)
    # return send_file(urlnode.body, mimetype='application/zip',
    #                 as_attachment=True, attachment_filename='file.zip')
    with open('foo.bin', 'wb') as f:
        f.write(to_return.getvalue())
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
    i = 0
    titles = []
    if not os.path.exists(HAR_DIR):
        os.makedirs(HAR_DIR)
    for report_dir in get_report_dirs():
        har_files = sorted(glob(os.path.join(HAR_DIR, report_dir, '*.har')))
        if not har_files:
            continue
        with open(har_files[0], 'r') as f:
            j = json.load(f)
            titles.append((i, j['log']['pages'][0]['title']))
        i += 1

    return render_template('index.html', titles=titles)


if __name__ == '__main__':
    app.run(port=5001, threaded=True)
