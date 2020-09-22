#!/bin/bash

set -e
set -x

mkdir -p web/static/

wget -q https://d3js.org/d3.v5.min.js -O web/static/d3.v5.min.js

datatables="1.10.22"

wget -q https://cdn.datatables.net/v/bs4/dt-${datatables}/datatables.min.css -O web/static/datatables.min.css
wget -q https://cdn.datatables.net/v/bs4/dt-${datatables}/datatables.min.js -O web/static/datatables.min.js
