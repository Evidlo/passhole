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
from colorama import Fore, Back, Style
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

# create database
def init_database(args):

    # create database if it doesn't exist and if --database not given
    if not os.path.exists(args.database):
        log.info("Creating database at {}".format(args.database))
        shutil.copy(template_database_file, args.database)
        log.info("Enter your desired database password")
        password = getpass(Fore.GREEN + 'Password: ' + Fore.RESET)
        password_confirm = getpass(Fore.GREEN + 'Confirm: ' + Fore.RESET)
        if not password == password_confirm:
            log.info("Passwords do not match")
            sys.exit()
        kp = PyKeePass(args.database, password='password')
        kp.set_password(password)
        kp.save()
        kp.kdb.close()

# load database
def open_database(args):
    # check if database exists
    if not os.path.exists(args.database):
        log.error("No database found at {}. Run `passhole init`".format(args.database))
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

    log.debug("selected_entry:{}".format(selected_entry))

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
        log.info(Fore.GREEN + "Title: " + Fore.RESET + (entry.title or ''))
        log.info(Fore.GREEN + "Username: " + Fore.RESET + (entry.username or ''))
        log.info(Fore.GREEN + "Password: " + Fore.RESET +
                 Fore.RED + Back.RED + (entry.password or '') + Fore.RESET + Back.RESET)
        log.info(Fore.GREEN + "URL: " + Fore.RESET + (entry.url or ''))
    else:
        log.info("No entry {} found".format(args.entry_path))


# list entries as a tree
def list_entries(args):
    kp = open_database(args)

    def list_items(group, depth):
        log.info(Style.BRIGHT + Fore.BLUE +
                ' ' * depth + '[{}]'.format(group.name) +
                Style.RESET_ALL + Fore.RESET)
        for entry in sorted(group.entries, key=lambda x: x.__str__()):
            if entry == group.entries[-1]:
                log.info(' ' * depth + "└── {0}".format(entry.title))
            else:
                log.info(' ' * depth + "├── {0}".format(entry.title))
        for group in sorted(group.subgroups, key=lambda x: x.__str__()):
            list_items(group, depth+4)

    for entry in sorted(kp.root_group.entries, key=lambda x: x.__str__()):
        log.info(entry.title)
    for group in sorted(kp.root_group.subgroups, key=lambda x: x.__str__()):
        list_items(group, 0)


# create new entry/group
def add(args):
    kp = open_database(args)

    # process path into group path and entry title
    if '/' in args.path.strip('/'):
        [group_path, title] = args.path.strip('/').rsplit('/', 1)
    else:
        group_path = ''
        title = args.path.strip('/')
        if not title:
            log.info("No group name given")

    log.debug("args.path:{}".format(args.path))
    log.debug("group_path:{} , title:{}".format(group_path, title))

    parent_group = kp.find_groups_by_path(group_path, first=True)

    if parent_group is None:
        log.info("No such group '{}'".format(group_path))
        return

    # create a new group
    if args.path.endswith('/'):
        group = Group(title)
        parent_group.append(group)
        kp.save()

    # create a new entry
    else:
        username = raw_input(Fore.GREEN + 'Username: ' + Fore.RESET)

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
            password = getpass(Fore.GREEN + 'Password: ' + Fore.RESET)
            password_confirm = getpass(Fore.GREEN + 'Confirm: ' + Fore.RESET)
            if not password == password_confirm:
                log.info("Passwords do not match")
                sys.exit()

        url = raw_input(Fore.GREEN + 'URL: ' + Fore.RESET)
        kp.add_entry(parent_group, title, username, password, url=url)
        kp.save()


# remove an entry/group
def remove(args):
    kp = open_database(args)

    # remove a group
    if args.path.endswith('/'):
        group = kp.find_groups_by_path(args.path, first=True)
        if group:
            group.delete()
        else:
            log.info("No such group {}".format(args.path))

    # remove an entry
    else:
        entry = kp.find_entries_by_path(args.path, first=True)
        if entry:
            entry.delete()
        else:
            log.info("No such entry {}".format(args.path))

    kp.save()


def main():
    parser = argparse.ArgumentParser(description="Append -h to any command to view its syntax.")
    parser._positionals.title = "commands"


    subparsers = parser.add_subparsers()

    # process args for `show` command
    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', metavar='PATH', type=str, help="Path to KeePass entry")
    show_parser.set_defaults(func=show)

    # process args for `dmenu` command
    dmenu_parser = subparsers.add_parser('dmenu', help="select entries using dmenu (or any program that supports dmenu style input) and send to keyboard")
    dmenu_parser.add_argument('prog', metavar='PROG', nargs='?', default='dmenu', help="dmenu-like program to call")
    dmenu_parser.add_argument('--tabbed', action='store_true', default=False, help="type out username and password (tab separated) when using --dmenu")
    dmenu_parser.set_defaults(func=dmenu_entries)

    # process args for `add` command
    add_parser = subparsers.add_parser('add', help="add new entry (e.g. `foo`) or group (e.g. `foo/`)")
    add_parser.add_argument('path', metavar='PATH', type=str, help="path to new KeePass entry/group")
    add_parser.add_argument('-w', '--words', metavar='length', type=int, nargs='?', const=5, default=None, help="generate 'correct horse battery staple' style password (https://xkcd.com/936/) when creating entry ")
    add_parser.add_argument('-a', '--alphanumeric', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric password")
    add_parser.add_argument('-s', '--symbolic', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric + symbolic password")
    add_parser.set_defaults(func=add)

    # process args for `remove` command
    remove_parser = subparsers.add_parser('remove', help="remove an entry (e.g. `foo`) or group (e.g. `foo/`)")
    remove_parser.add_argument('path', metavar='PATH', type=str, help="path to KeePass entry/group to delete")
    remove_parser.set_defaults(func=remove)

    # process args for `list` command
    list_parser = subparsers.add_parser('list', help="list entries in the database")
    list_parser.set_defaults(func=list_entries)

    # process args for `init` command
    list_parser = subparsers.add_parser('init', help="initialize a new database (default ~/.passhole.kdbx)")
    list_parser.set_defaults(func=init_database)

    # optional arguments
    parser.add_argument('--debug', action='store_true', default=False, help="enable debug messages")
    parser.add_argument('--database', metavar='PATH', type=str, default=database_file, help="use a different database path")
    version_info = str(pkg_resources.require('passhole')[0])
    parser.add_argument('-v', '--version', action='version', version=version_info, help="show version information")


    args = parser.parse_args()

    if args.debug:
        log.info('Debugging enabled...')
        log.setLevel(logging.DEBUG)


    args.func(args)

if __name__ == '__main__':
    main()
