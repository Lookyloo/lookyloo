# PyLookyloo

This is the client API for [Lookyloo](https://github.com/Lookyloo/lookyloo).

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
  --listing      Should the report be publicly listed.
  --redirects    Get redirects for a given capture.

The response is the permanent URL where you can see the result of the capture.
```

* Or as a library

```python

from pylookyloo import Lookyloo

lookyloo = Lookyloo('https://url.of.lookyloo.instance')
if lookyloo.is_up:  # to make sure it is up and reachable
	permaurl = lookyloo.enqueue('http://url.to.lookup')

```
You can add the following paramaters to the enqueue fuction:
```
    quiet      Return only the uuid
    listing    Should the report be publicly listed.
    user_agent Set your own user agent
    Depth      Set the analysis depth. Can not be more than in config
```
To retrieve the redirects (json)
```python
    redirect = lookyloo.get_redirects(uuid)
```
To retrieve the cookies (json)
```python
    cookies = lookyloo.get_cookies(uuid)
```
To retrieve the screenshot (raw)
```python
    screen = lookyloo.get_screenshot(uuid)
```
To retrieve the html (raw)
```python
    html = lookyloo.get_html(uuid)
```
To retrieve the complete capture(raw)
```python
    capture = lookyloo.get_complete_capture(uuid)
```
