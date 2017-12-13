try:
    from setuptools import setup
except:
    from distutils.core import setup

import os


here = os.path.abspath(os.path.dirname(__file__))

long_description = open(os.path.join(here, 'README.rst'), 'rt').read()

setup(
    name = 'pydf2json',
    version = '2.0.8',
    packages=['pydf2json', 'pydf2json.scripts'],
    url = 'https://github.com/xamiel/pydf2json',
    license = 'GPL-3.0',
    author = 'Shane King',
    author_email = 'kinagling@meatchicken.net',
    description = 'PDF analysis. Convert contents of PDF to a JSON-style python dictionary.',
    long_description = long_description,
    entry_points = {
        'console_scripts': [
            'pydf.py = pydf2json.scripts.pydf:main'
        ]
    },
    python_requires = '>=2.6, <3',
    keywords = ['pdf', 'pydf2json', 'pdf analysis'],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows :: Windows 7',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Security'
    ]
)