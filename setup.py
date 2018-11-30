from setuptools import setup
from passhole import version

setup(
    name='passhole',
    version=version.__version__,
    packages=['passhole'],
    package_data={'passhole':['blank.kdbx', 'wordlist.txt']},
    author="Evan Widloski",
    author_email="evan@evanw.org",
    description="CLI KeePass client with dmenu support",
    long_description=open('README.rst').read(),
    license="GPLv3",
    keywords="keepass cli dmenu password store passwords manager rofi pykeepass libkeepass",
    url="https://github.com/evidlo/passhole",
    entry_points={
        'console_scripts': ['passhole = passhole.passhole:main', 'ph = passhole.passhole:main']
    },
    install_requires=[
        "pynput",
        "pykeepass",
        "colorama",
        "pygpgme",
        "future"
    ],
    data_files=[('share/man/man1', ['passhole.1'])],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ]
)
