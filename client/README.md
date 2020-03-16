# PyLookyloo

This is the client API for [Lookyloo](https://github.com/CIRCL/lookyloo).

## Installation

```bash
pip install pylookyloo
```

## Usage

* You can use the lookyloo command to enqueue an URL.

```bash
usage: lookyloo [-h] [--url URL] --query QUERY

Enqueue a URL on Lookyloo.

optional arguments:
  -h, --help     show this help message and exit
  --url URL      URL of the instance (defaults to https://lookyloo.circl.lu/,
                 the public instance).
  --query QUERY  URL to enqueue.

The response is the permanent URL where you can see the result of the capture.
```

* Or as a library

```python

from pylookyloo import Lookyloo

lookyloo = Lookyloo('https://url.of.lookyloo.instance')
if lookyloo.is_up():  # to make sure it is up and reachable
	permaurl = lookyloo.enqueue('http://url.to.lookup')

```
