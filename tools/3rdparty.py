#!/usr/bin/env python3

import hashlib
import io
import shutil
import subprocess
import tarfile
import tempfile

from pathlib import Path

import requests

from lookyloo.default import get_homedir

d3js_version = '7.9.1'
jquery_version = "3.7.1"
datatables_version = "3.1.5"
datatables_rowgroup_version = "2.1.1"
datatables_buttons_version = "4.1.3"
datatables_select_version = "4.1.1"
jquery_json_viewer_version = "1.5.0"

# Vitrine (https://github.com/ecrou-exact/vitrine): web components of the capture
# panels (JSON viewer, tables, stats...). Source of a pinned commit, SHA-256
# checked, built with Node >= 20 (npm ci --ignore-scripts + node scripts/build.js).
VITRINE_COMMIT = '1f79d7c6914f0222584c9b8e0111597d27a24f05'
VITRINE_TARBALL = f'https://codeload.github.com/ecrou-exact/vitrine/tar.gz/{VITRINE_COMMIT}'
VITRINE_SHA256 = '91be915c238f2ba220377f015bf1da480e39af2a23a2ddf499376f3a056cf4ba'
# What the website needs from vitrine's dist/
VITRINE_KEEP = ('esm', 'languages', 'syntax-themes', 'vendor', 'vitrine.css')


def install_vitrine(dest_dir: Path) -> None:
    '''Build vitrine at VITRINE_COMMIT and keep its ES modules in vendor/vitrine/.'''
    if not shutil.which('node') or not shutil.which('npm'):
        raise SystemExit('Vitrine is built with Node >= 20: node and npm were not found.')
    response = requests.get(VITRINE_TARBALL, timeout=120)
    response.raise_for_status()
    if hashlib.sha256(response.content).hexdigest() != VITRINE_SHA256:
        raise SystemExit(f'Vitrine {VITRINE_COMMIT[:10]}: SHA-256 mismatch, refusing to build it.')
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
            tar.extractall(tmp, filter='data')
        source = Path(tmp) / f'vitrine-{VITRINE_COMMIT}'
        subprocess.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=source, check=True)
        subprocess.run(['node', 'scripts/build.js'], cwd=source, check=True)
        target = dest_dir / 'vitrine'
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        for name in VITRINE_KEEP:
            built = source / 'dist' / name
            if built.is_dir():
                shutil.copytree(built, target / name, ignore=shutil.ignore_patterns('*.map'))
            elif built.exists():
                shutil.copy2(built, target / name)
        (target / 'COMMIT').write_text(VITRINE_COMMIT + '\n')
    print(f'Built vitrine {VITRINE_COMMIT[:10]}.')


if __name__ == '__main__':
    dest_dir = get_homedir() / 'website' / 'web' / 'static' / 'vendor'
    dest_dir.mkdir(parents=True, exist_ok=True)

    d3 = requests.get(f'https://cdn.jsdelivr.net/npm/d3@{d3js_version}/dist/d3.min.js')
    with (dest_dir / 'd3.min.js').open('wb') as f:
        f.write(d3.content)
        print(f'Downloaded d3js v{d3js_version}.')

    jquery = requests.get(f'https://code.jquery.com/jquery-{jquery_version}.min.js')
    with (dest_dir / 'jquery.min.js').open('wb') as f:
        f.write(jquery.content)
        print(f'Downloaded jquery v{jquery_version}.')

    datatables_js = requests.get(f'https://cdn.datatables.net/v/bs5/dt-{datatables_version}/b-{datatables_buttons_version}/rg-{datatables_rowgroup_version}/sl-{datatables_select_version}/datatables.min.js')
    with (dest_dir / 'datatables.min.js').open('wb') as f:
        f.write(datatables_js.content)
        print(f'Downloaded datatables js v{datatables_version}.')

    datatables_css = requests.get(f'https://cdn.datatables.net/v/bs5/dt-{datatables_version}/b-{datatables_buttons_version}/rg-{datatables_rowgroup_version}/sl-{datatables_select_version}/datatables.min.css')
    with (dest_dir / 'datatables.min.css').open('wb') as f:
        f.write(datatables_css.content)
        print(f'Downloaded datatables_css v{datatables_version}.')

    jquery_json_js = requests.get(f'https://cdn.jsdelivr.net/npm/jquery.json-viewer@{jquery_json_viewer_version}/json-viewer/jquery.json-viewer.js')
    with (dest_dir / 'jquery.json-viewer.js').open('wb') as f:
        f.write(jquery_json_js.content)
        print(f'Downloaded jquery_json js v{jquery_json_viewer_version}.')

    jquery_json_css = requests.get(f'https://cdn.jsdelivr.net/npm/jquery.json-viewer@{jquery_json_viewer_version}/json-viewer/jquery.json-viewer.css')
    with (dest_dir / 'jquery.json-viewer.css').open('wb') as f:
        f.write(jquery_json_css.content)
        print(f'Downloaded jsontree css v{jquery_json_viewer_version}.')

    install_vitrine(dest_dir)

    print('All 3rd party modules for the website were downloaded.')
