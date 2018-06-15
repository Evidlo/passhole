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
    url="https://github.com/purduelug/passhole",
    entry_points={
        'console_scripts': ['passhole = passhole.passhole:main', 'ph = passhole.passhole:main']
    },
    install_requires=[
        "PyUserInput",
        "pykeepass",
        "colorama",
        "pygpgme",
        "future"
    ],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ]
)
