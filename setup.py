#!/usr/bin/env python
# coding: utf-8

# Copyright (c) Juptyer Development Team.
# Distributed under the terms of the Modified BSD License.

#-----------------------------------------------------------------------------
# Minimal Python version sanity check (from IPython/Jupyterhub)
#-----------------------------------------------------------------------------

from __future__ import print_function

import os
import sys

from setuptools import setup
from pathlib import Path

pjoin = os.path.join

HERE = Path(__file__).parent.resolve()


# directory for the templates ...
share_jupyterhub = HERE / 'share' /  'jupyterhub'


def get_data_files():
    """Get data files in share/jupyter"""

    data_files = []
    ntrim = len(str(HERE / os.path.sep))

    for (d, dirs, filenames) in os.walk(share_jupyterhub):
        data_files.append((d[ntrim:], [pjoin(d, f) for f in filenames]))
    return data_files



# Get the current package version.
version_ns = {}
with open(HERE / 'version.py') as f:
    exec(f.read(), {}, version_ns)

long_description = (HERE / "README.md").read_text()

setup_args = dict(
    name                = 'jhub_shibboleth_user_authenticator',
    packages            = ['jhub_shibboleth_user_authenticator'],
    version             = version_ns['__version__'],
    description         = """REMOTE_USER Authenticator (Shibboleth variant): An Authenticator for Jupyterhub to read user information from HTTP request headers, as when running behind an authenticating proxy.""",
    long_description    = long_description,
    long_description_content_type="text/markdown",
    author              = "Oliver Cordes (https://github.com/ocordes)",
    author_email        = "ocordes@astro.uni-bonn.de",
    url                 = "https://github.com/ocordes/jhub_shibboleth_user_authenticator",
    license             = "GPLv3",
    platforms           = "Linux, Mac OS X",
    keywords            = ['Interactive', 'Interpreter', 'Shell', 'Web'],
    classifiers         = [
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    data_files          = get_data_files()
)

# setuptools requirements
if 'setuptools' in sys.modules:
    setup_args['install_requires'] = install_requires = []
    install_requires.append('jupyterhub')

def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()
