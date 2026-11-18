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
# World map of the geolocation card of the IPs (js/components/ip_geo.js)
world_atlas_version = '2.0.2'
topojson_client_version = '3.1.0'
jquery_version = "3.7.1"
datatables_version = "3.1.5"
datatables_rowgroup_version = "2.1.1"
datatables_buttons_version = "4.1.3"
datatables_select_version = "4.1.1"
jquery_json_viewer_version = "1.5.0"

# Vitrine (https://github.com/ecrou-exact/vitrine): web components of the capture
# panels (JSON viewer, tables, stats...). Source of a pinned commit, SHA-256
# checked, built with Node >= 20 (npm ci --ignore-scripts + node scripts/build.js).
VITRINE_COMMIT = 'd0dd8410755d2982464b64e0278cdc0f8ef378f7'
VITRINE_TARBALL = f'https://codeload.github.com/ecrou-exact/vitrine/tar.gz/{VITRINE_COMMIT}'
VITRINE_SHA256 = 'fb5c1e38c417423085360379eb6739967c9281f3f4fefaee8f6c306ab3ad362d'
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


# Logo of MISP 3 (Analysis > Search events on MISP): the horizontal logo of the
# MISP web interface, for the light and the dark theme, from the MISP repository at
# a pinned commit of 3.0_wip, checked with their SHA-256
MISP_LOGO_COMMIT = '1c09fd609d0fda6423a99ca1ed4505f2a45b7a13'
MISP_LOGOS = {
    'misp-logo-horizontal.png': 'f57abf0df2f4f35012b44ae1335d80fc66752d81eaea1f2e7a27d11ac908b292',
    'misp-logo-horizontal-light.png': '07b0d8245f412d82ddc08f757a1441a95cd277d8c5863de2a44c0a3d205784dc',
}


def install_misp_logo(dest_dir: Path) -> None:
    (dest_dir / 'logos').mkdir(parents=True, exist_ok=True)
    for name, sha256 in MISP_LOGOS.items():
        response = requests.get(f'https://raw.githubusercontent.com/MISP/MISP/{MISP_LOGO_COMMIT}/app/webroot/img/{name}', timeout=60)
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != sha256:
            raise SystemExit(f'MISP logo {name}: SHA-256 mismatch, refusing to install it.')
        (dest_dir / 'logos' / name).write_bytes(response.content)
    print(f'Downloaded the MISP logos ({MISP_LOGO_COMMIT[:10]}).')


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

    world = requests.get(f'https://cdn.jsdelivr.net/npm/world-atlas@{world_atlas_version}/countries-110m.json')
    with (dest_dir / 'countries-110m.json').open('wb') as f:
        f.write(world.content)
        print(f'Downloaded world-atlas v{world_atlas_version}.')

    topojson = requests.get(f'https://cdn.jsdelivr.net/npm/topojson-client@{topojson_client_version}/dist/topojson-client.min.js')
    with (dest_dir / 'topojson-client.min.js').open('wb') as f:
        f.write(topojson.content)
        print(f'Downloaded topojson-client v{topojson_client_version}.')

    install_vitrine(dest_dir)
    install_misp_logo(dest_dir)

    print('All 3rd party modules for the website were downloaded.')
