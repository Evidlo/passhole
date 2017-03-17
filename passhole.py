#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Jack Cottom, Evan Widloski - 2017-03-07
## Passhole - Keepass CLI + dmenu interface


from pykeepass import PyKeePass
from subprocess import Popen, PIPE, STDOUT # for talking to dmenu programs
from pykeyboard import PyKeyboard          # for sending password to keyboard
import random
import os
import shutil
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger(__name__)

password_file = os.path.expanduser('~/.passhole.kdbx')

base_dir = os.path.dirname(os.path.realpath(__file__))
# taken from http://www.mit.edu/~ecprice/wordlist.10000
wordlist = os.path.join(base_dir, 'wordlist.10000')
template_password_file = os.path.join(base_dir, '.passhole.kdbx')

# create database if necessary
if not os.path.exists(password_file):
    log.info("No database file found at {0}".format(password_file))
    log.info("Creating it...")
    shutil.copy(template_password_file, password_file)

# load database
kp = PyKeePass(password_file, password='shatpass')

# generate a list of random words, `num_words` long
def word_sequence(num_words):
    selected_words = []
    with open(wordlist, 'r') as f:
        words = f.read().splitlines()
        for _ in range(0, num_words):
            selected_words.append(random.choice(words))

        return selected_words


# select an entry using `prog`, then type the password
# if `tabbed` is True, type out username, TAB, password
def dmenu(args):
    entries = kp.entries
    if not entries:
        entries = []
    entry_titles = '\n'.join([entry.title for entry in entries])

    # get the entry from dmenu
    p = Popen(args.prog, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    grep_stdout = p.communicate(input=entry_titles)[0]
    entry_title = grep_stdout.decode().rstrip('\n')

    if entry_title:
        entry = kp.find_entries_by_title(entry_title)[0]

        # type out password
        k = PyKeyboard()
        if args.tabbed:
            k.type_string(entry.username)
            k.tap_key(k.tab_key)
        k.type_string(entry.password)


# print out the contents of an entry
def show(args):
    entry = kp.find_entries_by_path(args.entry_path, first=True)
    print('Title: ' + (entry.title or ''))
    print('Username: ' + (entry.username or ''))
    print('Password: ' + (entry.password or ''))
    print('URL: ' + (entry.url or ''))


# list entries as a tree
def list_entries(args):
    def list_items(group, depth):
        print(' ' * depth + '[{}]'.format(group.name))
        for entry in group.entries:
            if entry == group.entries[-1]:
                print(' ' * depth + '└── {0}'.format(entry.title))
            else:
                print(' ' * depth + '├── {0}'.format(entry.title))
        for group in group.subgroups:
            list_items(group, depth+4)

    list_items(kp.root_group, 0)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # parser.add_argument('--dmenu', metavar='PROG', help="select passwords using dmenu (or any program that supports dmenu style line-separated input)")

    subparsers = parser.add_subparsers()

    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', type=str, help="Path to KeePass entry")
    show_parser.set_defaults(func=show)

    dmenu_parser = subparsers.add_parser('dmenu', help="select entries using dmenu (or any program that supports dmenu style input) and type them out")
    dmenu_parser.add_argument('prog', nargs='?', default='dmenu', help="dmenu-like program to call")
    dmenu_parser.add_argument('--tabbed', action='store_true', default=False, help="type out username and password (tab separated) when using --dmenu")
    dmenu_parser.add_argument('--generate', action='store_true', help="")
    dmenu_parser.set_defaults(func=dmenu)


    list_parser = subparsers.add_parser('list', help="list entries in the database")
    list_parser.set_defaults(func=list_entries)

    args = parser.parse_args()
    args.func(args)
