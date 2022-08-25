from setuptools import setup
from passhole import version
import shutil
import os

setup(
    name='passhole',
    version=version.__version__,
    packages=['passhole'],
    package_data={'passhole':['blank.kdbx', 'wordlist.txt']},
    author="Evan Widloski",
    author_email="evan@evanw.org",
    description="CLI KeePass client with dmenu support",
    long_description=open('README.rst').read(),
    long_description_content_type='text/x-rst',
    license="GPLv3",
    keywords="keepass cli dmenu password store passwords manager rofi pykeepass libkeepass",
    url="https://github.com/evidlo/passhole",
    entry_points={
        'console_scripts': ['passhole = passhole.passhole:main', 'ph = passhole.passhole:main']
    },
    install_requires=[
        "pynput",
        "pykeepass>=4.0.3",
        "pykeepass_cache",
        "colorama",
        "future",
        "pyotp",
        "qrcode",
    ],
    data_files=[
        ('share/man/man1', ['passhole.1'] if os.path.exists('passhole.1') else []),
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ]
)
