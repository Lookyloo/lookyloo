#!/bin/bash

set -e
set -x

mkdir -p web/static/

wget -q https://d3js.org/d3.v5.min.js -O web/static/d3.v5.min.js

FileSaver="v2.0.2"

wget -q https://raw.githubusercontent.com/eligrey/FileSaver.js/${FileSaver}/src/FileSaver.js -O web/static/FileSaver.js

bootstrap_table="1.16.0"

wget -q https://unpkg.com/bootstrap-table@${bootstrap_table}/dist/bootstrap-table.min.css -O web/static/bootstrap-table.min.css
wget -q https://unpkg.com/bootstrap-table@${bootstrap_table}/dist/bootstrap-table.min.js -O web/static/bootstrap-table.min.js
