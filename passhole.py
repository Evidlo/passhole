#!/usr/bin/env python2
# -*- coding: utf-8 -*-
## Jack Cottom, Evan Widloski - 2017-03-07
## Passhole - Keepass CLI + dmenu interface


from pykeepass import PyKeePass, Group, Entry
from subprocess import Popen, PIPE, STDOUT # for talking to dmenu programs
from pykeyboard import PyKeyboard          # for sending password to keyboard
import random
import os
import shutil
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(message)s')
# hide INFO messages from pykeepass
logging.getLogger("pykeepass").setLevel(logging.WARNING)
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


# select an entry using `prog`, then type the password
# if `tabbed` is True, type out username, TAB, password
def dmenu_entries(args):
    def dmenu_items(parent_group, path):
        groups = ['[{}]'.format(group.name) for group in parent_group.subgroups]
        entries = [group.title for group in parent_group.entries]
        items = '\n'.join(groups + entries)

        # get the entry from dmenu
        p = Popen(args.prog, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout = p.communicate(input=items)[0].decode()
        selection = stdout.rstrip('\n').lstrip('[').rstrip(']')

        # if nothing was selected, return None
        if not selection:
            return None

        selected_item = (kp.find_entries_by_path(path + selection, first=True) or
                         kp.find_groups_by_path(path + selection, first=True))

        log.debug('selected_item:{}'.format(selected_item))

        # if a group was selected, descend into it
        if isinstance(selected_item, Group):
            return dmenu_items(selected_item, path + selected_item.name + '/')
        # if an entry was selected, we're done
        elif isinstance(selected_item, Entry):
            return path + selected_item.title

    entry_path = dmenu_items(kp.root_group, '')

    if entry_path:
        entry = kp.find_entries_by_path(entry_path, first=True)

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

    for entry in kp.root_group.entries:
        print(entry.title)
    for group in kp.root_group.subgroups:
        list_items(group, 0)


# create new entry/group
def add(args):

    if '/' in args.path:
        [group_path, title] = args.path.rsplit('/', 1)
    else:
        group_path = ''
        title = args.path

    log.debug("args.path:{}".format(args.path))
    log.debug("group_path:{} , title:{}".format(group_path, title))

    parent_group = kp.find_groups_by_path(group_path, first=True)

    if parent_group is None:
        print('No such group \'{}\''.format(group_path))
        return

    # create a new group
    if args.group:
        if title:
            group = Group(title)
            parent_group.append(group)
            kp.save()
        else:
            print('No group name given')

    # create a new entry
    else:
        if title:
            username = raw_input('Username: ')
            password = raw_input('Password: ')
            url = raw_input('URL: ')
            kp.add_entry(parent_group, title, username, password, url=url)
            kp.save()
        else:
            print('No entry title given')


# create new entry with generated password
def generate(args):
    if args.words:
        # generate a multi-word password, `words` words long
        selected_words = []
        with open(wordlist, 'r') as f:
            words = f.read().splitlines()
            for _ in range(0, num_words):
                selected_words.append(random.choice(words))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers()

    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', type=str, help="Path to KeePass entry")
    show_parser.set_defaults(func=show)

    dmenu_parser = subparsers.add_parser('dmenu', help="select entries using dmenu (or any program that supports dmenu style input) and type them out")
    dmenu_parser.add_argument('prog', nargs='?', default='dmenu', help="dmenu-like program to call")
    dmenu_parser.add_argument('--tabbed', action='store_true', default=False, help="type out username and password (tab separated) when using --dmenu")
    dmenu_parser.add_argument('--generate', action='store_true', help="")
    dmenu_parser.set_defaults(func=dmenu_entries)

    add_parser = subparsers.add_parser('add', help="add new entry or group")
    add_parser.add_argument('--group', action='store_true', help="create a new group instead of entry")
    add_parser.add_argument('path', type=str, help="path to new KeePass entry/group")
    add_parser.set_defaults(func=add)

    generate_parser = subparsers.add_parser('generate', help="add new entry with generated password")
    generate_parser.add_argument('entry_path', type=str, help="path to new KeePass entry")
    generate_parser.add_argument('--words', metavar='length', type=int, default=5, help="generate 'correct horse battery staple' style password (https://xkcd.com/936/)")
    generate_parser.set_defaults(func=generate)

    list_parser = subparsers.add_parser('list', help="list entries in the database")
    list_parser.set_defaults(func=list_entries)

    args = parser.parse_args()
    args.func(args)
