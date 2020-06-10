# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='pylookyloo',
    version='1.0-dev',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/Lookyloo/lookyloo/client',
    description='Python client for Lookyloo',
    packages=['pylookyloo'],
    entry_points={"console_scripts": ["lookyloo = pylookyloo:main"]},
    install_requires=['requests'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ]
)
