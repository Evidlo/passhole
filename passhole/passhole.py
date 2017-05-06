#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Evan Widloski - 2017-03-07
## Passhole - Keepass CLI + dmenu interface


from __future__ import absolute_import
from pykeepass.pykeepass import PyKeePass
from pykeepass.group import Group
from pykeepass.entry import Entry
from subprocess import Popen, PIPE, STDOUT # for talking to dmenu programs
from pykeyboard import PyKeyboard          # for sending password to keyboard
from getpass import getpass
import random
import os, sys
import shutil
import logging
import argparse
import pkg_resources


logging.basicConfig(level=logging.INFO, format='%(message)s')
# hide INFO messages from pykeepass
logging.getLogger("pykeepass").setLevel(logging.WARNING)
log = logging.getLogger(__name__)

database_file = os.path.expanduser('~/.passhole.kdbx')

base_dir = os.path.dirname(os.path.realpath(__file__))
# taken from http://www.mit.edu/~ecprice/wordlist.10000
wordlist_file = os.path.join(base_dir, 'wordlist.10000')
template_database_file = os.path.join(base_dir, 'blank.kdbx')

alphabetic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
numeric = '0123456789'
symbolic = '!@#$%^&*()_+-=[]{};:'"<>,./?\|`~"


# load database
def open_database(args):
    # check if database exists
    if not os.path.exists(args.database):
        log.error("No database found at {}".format(args.database))
        sys.exit()
    # check if running in interactive shell
    if False:
    # if os.isatty(sys.stdout.fileno()):
        password = getpass()
    else:
        NULL = open(os.devnull, 'w')
        p = Popen(["zenity", "--password"],
                  stdin=PIPE,
                  stdout=PIPE,
                  stderr=NULL,
                  close_fds=True)
        password = p.communicate()[0].decode().rstrip('\n')

    kp = PyKeePass(args.database, password=password)
    return kp

# select an entry using `prog`, then type the password
# if `tabbed` is True, type out username, TAB, password
def dmenu_entries(args):
    kp = open_database(args)

    entry_paths = [entry.path for entry in kp.entries]
    items = '\n'.join(entry_paths)

    # get the entry from dmenu
    p = Popen(args.prog, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    stdout = p.communicate(input=items)[0].decode()
    selection_path = stdout.rstrip('\n').lstrip('[').rstrip(']')

    # if nothing was selected, return None
    if not selection_path:
        return None

    selected_entry = kp.find_entries_by_path(selection_path, first=True)

    log.debug('selected_entry:{}'.format(selected_entry))

    # type out password
    k = PyKeyboard()
    if args.tabbed:
        if selected_entry.username:
            k.type_string(selected_entry.username)
            k.tap_key(k.tab_key)
        else:
            log.warning("Selected entry does not have a username")
    if entry.password:
        k.type_string(selected_entry.password)
    else:
        log.warning("Selected entry does not have a password")


# print out the contents of an entry
def show(args):
    kp = open_database(args)

    entry = kp.find_entries_by_path(args.entry_path, first=True)
    if entry:
        log.info('Title: ' + (entry.title or ''))
        log.info('Username: ' + (entry.username or ''))
        log.info('Password: ' + (entry.password or ''))
        log.info('URL: ' + (entry.url or ''))
    else:
        log.info('No entry {} found'.format(args.entry_path))


# list entries as a tree
def list_entries(args):
    kp = open_database(args)

    def list_items(group, depth):
        log.info(' ' * depth + '[{}]'.format(group.name))
        for entry in group.entries:
            if entry == group.entries[-1]:
                log.info(' ' * depth + '└── {0}'.format(entry.title))
            else:
                log.info(' ' * depth + '├── {0}'.format(entry.title))
        for group in group.subgroups:
            list_items(group, depth+4)

    for entry in kp.root_group.entries:
        log.info(entry.title)
    for group in kp.root_group.subgroups:
        list_items(group, 0)


# create new entry/group
def add(args):
    kp = open_database(args)

    # process path into group path and entry title
    if '/' in args.path.rstrip('/'):
        [group_path, title] = args.path.rstrip('/').rsplit('/', 1)
    else:
        group_path = ''
        title = args.path.rstrip('/')

    log.debug("args.path:{}".format(args.path))
    log.debug("group_path:{} , title:{}".format(group_path, title))

    parent_group = kp.find_groups_by_path(group_path, first=True)

    if parent_group is None:
        log.info('No such group \'{}\''.format(group_path))
        return

    # create a new group
    if args.path.endswith('/'):
        if title:
            group = Group(title)
            parent_group.append(group)
            kp.save()
        else:
            log.info('No group name given')

    # create a new entry
    else:
        if title:
            username = raw_input('Username: ')

            # generate correct-horse-battery-staple password
            if args.words:
                with open(wordlist_file, 'r') as f:
                    wordlist = f.read().splitlines()
                    selected = random.sample(wordlist, args.words)
                password =  '-'.join(selected)

            # generate alphanumeric password
            elif args.alphanumeric:
                selected = [random.choice(alphabetic + numeric) for _ in range(0, args.alphanumeric)]
                password = ''.join(selected)

            # generate alphanumeric + symbolic password
            elif args.symbolic:
                selected = [random.choice(alphabetic + numeric + symbolic) for _ in range(0, args.symbolic)]
                password = ''.join(selected)

            # prompt for password instead of generating it
            else:
                password = getpass('Password: ')
                password_confirm = getpass('Confirm: ')
                if not password == password_confirm:
                    log.info("Passwords do not match")

            url = raw_input('URL: ')
            kp.add_entry(parent_group, title, username, password, url=url)
            kp.save()
        else:
            log.info('No entry title given')


def main():
    parser = argparse.ArgumentParser(description="Passhole is hardcoded to read from ~/.passhole.kdbx.  Append -h to any command to view its syntax.")


    subparsers = parser.add_subparsers()

    # process args for `show` command
    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', type=str, help="Path to KeePass entry")
    show_parser.set_defaults(func=show)

    # process args for `dmenu` command
    dmenu_parser = subparsers.add_parser('dmenu', help="select entries using dmenu (or any program that supports dmenu style input) and type them out")
    dmenu_parser.add_argument('prog', nargs='?', default='dmenu', help="dmenu-like program to call")
    dmenu_parser.add_argument('--tabbed', action='store_true', default=False, help="type out username and password (tab separated) when using --dmenu")
    dmenu_parser.set_defaults(func=dmenu_entries)

    # process args for `add` command
    add_parser = subparsers.add_parser('add', help="add new entry (e.g. `foo`) or group (e.g. `foo/`)")
    add_parser.add_argument('path', type=str, help="path to new KeePass entry/group")
    add_parser.add_argument('-w', '--words', metavar='length', type=int, nargs='?', const=5, default=None, help="generate 'correct horse battery staple' style password (https://xkcd.com/936/) when creating entry ")
    add_parser.add_argument('-a', '--alphanumeric', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric password")
    add_parser.add_argument('-s', '--symbolic', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric + symbolic password")
    add_parser.set_defaults(func=add)

    # process args for `list` command
    list_parser = subparsers.add_parser('list', help="list entries in the database")
    list_parser.set_defaults(func=list_entries)

    # optional argument
    parser.add_argument('--debug', action='store_true', default=False, help="enable debug messages")
    parser.add_argument('--database', metavar='PATH', type=str, default=database_file, help="enable debug messages")
    version_info = str(pkg_resources.require('passhole')[0])
    parser.add_argument('--version', action='version', version=version_info)


    args = parser.parse_args()

    if args.debug:
        log.info('Debugging enabled...')
        log.setLevel(logging.DEBUG)

    # create database if it doesn't exist and if --database not given
    if not os.path.exists(database_file) and args.database == database_file:
        log.info("No database file found at {0}".format(database_file))
        log.info("Creating it...")
        shutil.copy(template_database_file, database_file)


    args.func(args)

if __name__ == '__main__':
    main()
