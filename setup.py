#from distutils.core import setup

try:
    from setuptools import setup
except:
    from distutils.core import setup

from os import path
#from codecs import open

here = path.abspath(path.dirname(__file__))

#with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
#    long_description = f.read()

long_description = open(path.join(here, 'README.rst'), 'rt').read()

setup(
    name = 'pydf2json',
    version = '0.1.0.dev3',
    packages=['pydf2json'],
    url = 'https://github.com/xamiel/pydf2json',
    license = 'GPL-3.0',
    author = 'Shane King',
    author_email = 'kinagling@meatchicken.net',
    description = 'PDF analysis tool utilizing PDF to JSON conversion.',
    long_description = long_description,
    scripts = ['pydf.py'],
    python_requires = '>=2.6, <3',
    keywords = 'pdf json pydf2json analysis',
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
