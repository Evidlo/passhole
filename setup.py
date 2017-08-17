from setuptools import setup

setup(
    name='passhole',
    version='1.3.0',
    packages=['passhole'],
    package_data={'passhole':['blank.kdbx', 'wordlist.10000']},
    author="Evan Widloski",
    author_email="evan@evanw.org",
    description="CLI KeePass client with dmenu support",
    long_description=open('README.rst').read(),
    license="MIT",
    keywords="keepass cli dmenu password store passwords manager rofi pykeepass libkeepass",
    url="https://github.com/purduelug/passhole",
    entry_points={
        'console_scripts': ['passhole = passhole.passhole:main']
    },
    install_requires=[
        "PyUserInput",
        "pykeepass",
        "colorama"
    ],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ]
)
