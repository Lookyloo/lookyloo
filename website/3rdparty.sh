#!/bin/bash

set -e
set -x

mkdir -p web/static/

wget https://d3js.org/d3.v5.min.js -O web/static/d3.v5.min.js

FileSaver="5733e40e5af936eb3f48554cf6a8a7075d71d18a"

wget https://cdn.rawgit.com/eligrey/FileSaver.js/${FileSaver}/FileSaver.js -O web/static/FileSaver.js
