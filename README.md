[![Lookyloo icon](website/web/static/lookyloo.jpeg)](https://www.lookyloo.eu/docs/main/index.html)

*[Lookyloo](https://lookyloo.circl.lu/)* is a web interface that captures a webpage and then displays a tree of the domains, that call each other.


[![Gitter](https://badges.gitter.im/Lookyloo/community.svg)](https://gitter.im/Lookyloo/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)


* [What is Lookyloo?](#whats-in-a-name)
* [REST API](#rest-api)
* [Install Lookyloo](#installation)
* [Lookyloo Client](#python-client)
* [Contributing to Lookyloo](#contributing-to-lookyloo)
  * [Code of Conduct](#code-of-conduct)
* [Support](#support)
  * [Security](#security)
  * [Credits](#credits)
  * [License](#license)



## What's in a name?!

```
Lookyloo ...

Same as Looky Lou; often spelled as Looky-loo (hyphen) or lookylou

1. A person who just comes to look.
2. A person who goes out of the way to look at people or something, often causing crowds and disruption.
3. A person who enjoys watching other people's misfortune. Oftentimes car onlookers that stare at a car accidents.

In L.A., usually the lookyloos cause more accidents by not paying full attention to what is ahead of them.
```
Source: [Urban Dictionary](https://www.urbandictionary.com/define.php?term=lookyloo)


## No, really, what is Lookyloo?

Lookyloo is a web interface that allows you to capture and map the journey of a website page.

Find all you need to know about Lookyloo on our [documentation website](https://www.lookyloo.eu/docs/main/index.html).

Here's an example of a Lookyloo capture of the site **github.com**
![Screenshot of Lookyloo capturing Github](https://www.lookyloo.eu/docs/main/_images/sample_github.png)

# REST API

The API is self documented with swagger. You can play with it [on the demo instance](https://lookyloo.circl.lu/doc/).

# Installation

Please refer to the [install guide](https://www.lookyloo.eu/docs/main/install-lookyloo.html).


# Python client

`pylookyloo` is the recommended client to interact with a Lookyloo instance.

It is avaliable on PyPi, so you can install it using the following command:

```bash
pip install pylookyloo
```

For more details on `pylookyloo`, read the overview [docs](https://www.lookyloo.eu/docs/main/pylookyloo-overview.html), the [documentation](https://pylookyloo.readthedocs.io/en/latest/) of the module itself, or the code in this [GitHub repository](https://github.com/Lookyloo/PyLookyloo).

# Notes regarding using S3FS for storage

## Directory listing

TL;DR: it is slow.

If you have many captures (say more than 1000/day), and store captures in a s3fs bucket mounted with s3fs-fuse,
doing a directory listing in bash (`ls`) will most probably lock the I/O for every process
trying to access any file in the whole bucket. The same will be true if you access the
filesystem using python methods (`iterdir`, `scandir`...))

A workaround is to use the python s3fs module as it will not access the filesystem for listing directories.
You can configure the s3fs credentials in `config/generic.json` key `s3fs`.

**Warning**: this will not save you if you run `ls` on a directoy that contains *a lot* of captures.

## Versioning

By default, a MinIO bucket (backend for s3fs) will have versioning enabled, wich means it
keeps a copy of every version of every file you're storing. It becomes a problem if you have a lot of captures
as the index files are updated on every change, and the max amount of versions is 10.000.
So by the time you have > 10.000 captures in a directory, you'll get I/O errors when you try
to update the index file. And you absolutely do not care about that versioning in lookyloo.

To check if versioning is enabled (can be either enabled or suspended):

```
mc version info <alias_in_config>/<bucket>
```

The command below will suspend versioning:

```bash
mc version suspend <alias_in_config>/<bucket>
```

### I'm stuck, my file is raising I/O errors 

It will happen when your index was updated 10.000 times and versioning was enabled.

This is how to check you're in this situation: 

* Error message from bash (unhelpful):

```bash
$ (git::main) rm /path/to/lookyloo/archived_captures/Year/Month/Day/index
rm: cannot remove '/path/to/lookyloo/archived_captures/Year/Month/Day/index': Input/output error
```

* Check with python

```python
from lookyloo.default import get_config
import s3fs

s3fs_config = get_config('generic', 's3fs')
s3fs_client = s3fs.S3FileSystem(key=s3fs_config['config']['key'],
                                secret=s3fs_config['config']['secret'],
                                endpoint_url=s3fs_config['config']['endpoint_url'])

s3fs_bucket = s3fs_config['config']['bucket_name']
s3fs_client.rm_file(s3fs_bucket + '/Year/Month/Day/index')
```

* Error from python (somewhat more helpful):

```
OSError: [Errno 5] An error occurred (MaxVersionsExceeded) when calling the DeleteObject operation: You've exceeded the limit on the number of versions you can create on this object
```

* **Solution**: run this command to remove all older versions of the file 

```bash
mc rm --non-current --versions --recursive --force <alias_in_config>/<bucket>/Year/Month/Day/index
```

# Contributing to Lookyloo
To learn more about contributing to Lookyloo, see our [contributor guide](https://www.lookyloo.eu/docs/main/contributing.html).

### Code of Conduct
At Lookyloo, we pledge to act and interact in ways that contribute to an open, welcoming, diverse, inclusive, and healthy community. You can access our Code of Conduct [here](https://github.com/Lookyloo/lookyloo/blob/main/code_of_conduct.md) or on the [Lookyloo docs site](https://www.lookyloo.eu/docs/main/code-conduct.html).


# Support
 * To engage with the Lookyloo community contact us on [Gitter](https://gitter.im/lookyloo-app/community).
 * Let us know how we can improve Lookyloo by opening an [issue](https://github.com/Lookyloo/lookyloo/issues/new/choose).
 * Follow us on [Twitter](https://twitter.com/lookyloo_app).

### Security
To report vulnerabilities, see our [Security Policy](SECURITY.md).

### Credits
Thank you very much [Tech Blog @ willshouse.com](https://techblog.willshouse.com/2012/01/03/most-common-user-agents/) for the up-to-date list of UserAgents.

### License
See our [LICENSE](LICENSE).
