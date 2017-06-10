import os
import sys

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
py_version = sys.version_info[:2]
if py_version < (3, 4):
    raise Exception("aioimaplib requires Python >= 3.4.")

with open(os.path.join(here, 'README.rst')) as readme:
    README = readme.read()
with open(os.path.join(here, 'CHANGES.rst')) as changes:
    CHANGES = changes.read()

NAME = 'aioimaplib'

requires = [
]

setup(
    name=NAME,
    version='0.7.0',
    description='Python asyncio IMAP4rev1 client library',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Communications :: Email :: Post-Office :: IMAP",
        "Topic :: Internet" 
    ],
    author='Bruno Thomas',
    author_email='bruno@barreverte.fr',
    license='GPL-3.0',
    url='https://github.com/bamthomas/aioimaplib',
    keywords='asyncio mail imap',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    test_suite="nose.collector",  
    install_requires=requires,
)
