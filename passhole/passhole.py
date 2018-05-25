#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Evan Widloski - 2017-03-07
# Passhole - Keepass CLI + dmenu interface

from __future__ import absolute_import
from __future__ import print_function
from builtins import input
from .version import __version__
from pykeepass.pykeepass import PyKeePass
from subprocess import Popen, PIPE, STDOUT
from pykeyboard import PyKeyboard
from getpass import getpass
from colorama import Fore, Back, Style
from base64 import b64encode
from io import BytesIO
import gpgme
import random
import os
import sys
import shutil
import logging
import argparse
import readline


logging.basicConfig(level=logging.INFO, format='%(message)s')
# hide INFO messages from pykeepass
logging.getLogger("pykeepass").setLevel(logging.WARNING)
log = logging.getLogger(__name__)

database_file = os.path.expanduser('~/.passhole.kdbx')
keyfile_path = os.path.expanduser('~/.passhole.key')
passhole_cache = os.path.expanduser('~/.cache/passhole_cache')

base_dir = os.path.dirname(os.path.realpath(__file__))
# taken from https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases 
wordlist_file = os.path.join(base_dir, 'wordlist.txt')
template_database_file = os.path.join(base_dir, 'blank.kdbx')

alphabetic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
numeric = '0123456789'
symbolic = '!@#$%^&*()_+-=[]{};:'"<>,./?\|`~"
string_fields = {'username':'UserName', 'url':'URL', 'password':'Password', 'notes':'Notes'}

gpg = gpgme.Context()

def red(text):
    return Fore.RED + text + Fore.RESET
def green(text):
    return Fore.GREEN + text + Fore.RESET
def blue(text):
    return Fore.BLUE + text + Fore.RESET
def bold(text):
    return Style.BRIGHT + text + Style.NORMAL


# create database
def init_database(args):

    # create database if it doesn't exist
    if not os.path.exists(args.database):
        print("Enter your desired database password")
        password = getpass(green('Password: '))
        password_confirm = getpass(green('Confirm: '))

        if not password == password_confirm:
            log.error(red("Passwords do not match"))
            sys.exit()

        print("Creating database at {}".format(bold(args.database)))
        shutil.copy(template_database_file, args.database)

        use_keyfile = input("Would you like to generate a keyfile? (Y/n): ")
        # dont use a keyfile
        if use_keyfile == 'n':
            keyfile = None
        # generate a random AES256 keyfile
        else:
            keyfile = keyfile_path if not args.keyfile else args.keyfile

            log.debug("Looking for keyfile at {}".format(keyfile))
            if os.path.exists(keyfile):
                print("Found existing keyfile at {}  Exiting".format(bold(keyfile)))
                sys.exit()

            with open(keyfile, 'w') as f:
                contents = '''
                <?xml version="1.0" encoding="UTF-8"?>
                <KeyFile>
                    <Meta><Version>1.00</Version></Meta>
                    <Key><Data>{}</Data></Key>
                </KeyFile>
                '''
                log.debug("keyfile contents {}".format(contents))
                f.write(contents.format(b64encode(os.urandom(32)).decode()))

        # create database
        kp = PyKeePass(args.database, password='password')
        kp.set_credentials(password=password, keyfile=keyfile)
        kp.save()
        # create password cache
        if password and not args.no_cache:
            create_password_cache(args.cache, password, args.gpgkey)

    # quit if database already exists
    else:
        log.error(red("Found existing file at ") + bold(args.database))
        sys.exit()


# cache database password to a gpg encrypted file
def create_password_cache(cache, password, fingerprint):
    # get GPG key for creating cache
    keys = list(gpg.keylist())
    if keys:
        # get the gpg key specified
        if fingerprint:
            log.debug("Selected fingerprint: {}".format(fingerprint))
            try:
                selected_key = gpg.get_key(fingerprint.replace(' ', ''))
            except gpgme.GpgmeError:
                log.error(red("Specified GPG key not found"))
        # otherwise get the first key
        else:
            selected_key = keys[0]
    else:
        log.error(red("no GPG keys found. Try ") +
                  bold("gpg2 --gen-key") + red(" or use the ") +
                  bold("--no-cache") + red(" option"))
        sys.exit()

    # encrypt password and write to cache file
    infile = BytesIO(password.encode('utf8'))
    try:
        with open(cache, 'wb') as outfile:
            gpg.encrypt([selected_key], 0, infile, outfile)
    except gpgme.GpgmeError as e:
        # gpgkey is not trusted
        if e.code == gpgme.ERR_UNUSABLE_PUBKEY:
            log.error(red("Your GPG key is untrusted.  Run " + bold("gpg2 --edit-key \"{}\" trust".format(selected_key.uids[0].name)) + red(" to change the trust level")))
            os.remove(cache)
            sys.exit()
        else:
            raise e

    infile.close()


# load database
def open_database(args):
    # check if database exists
    if not os.path.exists(args.database):
        log.error(red("No database found at ") + bold(args.database) +  red(".  Run ") +  bold("ph init"))
        sys.exit()
    # check if keyfile exists, try to use default keyfile
    if args.no_keyfile:
        keyfile = None
    else:
        if not args.keyfile:
            if os.path.exists(keyfile_path):
                keyfile = keyfile_path
            else:
                keyfile = None
        else:
            if os.path.exists(args.keyfile):
                keyfile = args.keyfile
            else:
                log.error(red("No keyfile found at ") + bold(args.keyfile))
                sys.exit()

    if args.no_password:
        password = None
    else:
        # retrieve password from cache
        if os.path.exists(os.path.expanduser(args.cache)) and not args.no_cache:
            log.debug("Retrieving password from {}".format(args.cache))
            outfile = BytesIO()
            with open(args.cache, 'rb') as infile:
                try:
                    gpg.decrypt(infile, outfile)
                except gpgme.GpgmeError as e:
                    if e.code == gpgme.ERR_DECRYPT_FAILED:
                        log.error(red("Could not decrypt cache"))
                        sys.exit()
                    else:
                        raise e

            password = outfile.getvalue().decode('utf8')
            outfile.close()
        # if no cache, prompt for password and save it to cache
        else:
            # check if running in interactive shell
            if os.isatty(sys.stdout.fileno()):
                password = getpass('Enter password: ')
            # otherwise use zenity
            else:
                NULL = open(os.devnull, 'w')
                p = Popen(["zenity", "--entry", "--hide-text", "--text='Enter password'"],
                        stdin=PIPE,
                        stdout=PIPE,
                        stderr=NULL,
                        close_fds=True)
                password = p.communicate()[0].decode('utf-8').rstrip('\n')

            if password:
                if not args.no_cache:
                    create_password_cache(args.cache, password, args.gpgkey)
            else:
                log.error(red("No password given"))
                sys.exit()

    log.debug("opening {} with password:{} and keyfile:{}".format(args.database, str(password), str(keyfile)))
    try:
        kp = PyKeePass(args.database, password=password, keyfile=keyfile)
    except IOError:
        log.error(red("Password or keyfile incorrect"))
        if os.path.exists(os.path.expanduser(args.cache)) and not args.no_cache:
            log.error(red("Try clearing the cache at ") + bold(args.cache))
        sys.exit()
    return kp


# select an entry using `prog`, then type the password
# if `tabbed` is True, type out username, TAB, password
def type_entries(args):
    kp = open_database(args)

    entry_paths = [entry.path for entry in kp.entries if entry.title]
    entry_texts = []
    for entry in kp.entries:
        if args.username:
            entry_texts.append("{} ({})".format(str(entry.path), str(entry.username)))
        else:
            entry_texts.append("{}".format(str(entry.path)))

    items = '\n'.join(sorted(entry_texts))

    # get the entry from dmenu
    p = Popen(args.prog, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
    stdout = p.communicate(input=items.encode('utf-8'))[0].decode('utf-8')
    selection_path = stdout.rstrip('\n').lstrip('[').rstrip(']')

    # if nothing was selected, return None
    if not selection_path:
        log.warning("No path returned by {}".format(args.prog))
        return

    selected_entry = kp.find_entries(path=selection_path, first=True)

    if not selected_entry:
        log.warning("No such entry {}".format(selection_path))
        return

    log.debug("selected_entry:{}".format(selected_entry))

    # type out password
    k = PyKeyboard()
    if args.tabbed:
        if selected_entry.username:
            k.type_string(selected_entry.username)
            k.tap_key(k.tab_key)
        else:
            log.warning("Selected entry does not have a username")
    if selected_entry.password:
        k.type_string(selected_entry.password)
    else:
        log.warning("Selected entry does not have a password")


# print out the contents of an entry
def show(args):
    kp = open_database(args)

    entry = kp.find_entries(path=args.entry_path, first=True)
    if entry:
        # show specified field
        if args.field:
            # handle lowercase field input gracefully
            if args.field in string_fields.keys():
                args.field = string_fields[args.field]
            if args.field in entry._get_string_field_keys():
                print(entry._get_string_field(args.field), end='')
            else:
                log.error(red("Invalid field ") + bold(args.field.lower()))
        # otherwise, show all fields
        else:
            print(green("Title: ") + (entry.title or ''))
            print(green("Username: ") + (entry.username or ''))
            print(green("Password: ") +
                    Fore.RED + Back.RED + (entry.password or '') + Fore.RESET + Back.RESET)
            print(green("URL: ") + (entry.url or ''))
            for field_name, field_value in entry.custom_properties.items():
                print(green("{}: ".format(field_name)) + str(field_value or ''))
    else:
        log.error(red("No such entry ") + bold(args.entry_path))


# list entries as a tree
def list_entries(args):
    kp = open_database(args)

    # recursive function to list items in a group
    def list_items(group, prefix, show_branches=True):
        branch_corner = "└── " if show_branches else ""
        branch_tee = "├── " if show_branches else ""
        branch_pipe = "│   " if show_branches else ""
        branch_blank = "    " if show_branches else ""
        # branch_corner = branch_tee = branch_pipe = "    " if show_branches else ""
        entries = sorted(group.entries, key=lambda x: str(x.title))
        for entry in entries:
            if args.username:
                entry_string = "{} ({})".format(str(entry.title), str(entry.username))
            else:
                entry_string = "{}".format(str(entry.title))

            if entry == entries[-1] and len(group.subgroups) == 0:
                print(prefix + branch_corner + entry_string)
            else:
                print(prefix + branch_tee + entry_string)
        groups = sorted(group.subgroups, key=lambda x: x.__str__())
        for group in groups:
            if group == groups[-1]:
                print(prefix + branch_corner + blue(bold(str(group.name))))
                list_items(group, prefix + branch_blank)
            else:
                print(prefix + branch_tee + blue(bold(str(group.name))))
                list_items(group, prefix + branch_pipe)

    list_items(kp.root_group, "", show_branches=False)


# search all string fields for a string
def grep(args):
    kp = open_database(args)

    flags = 'i' if args.i else None
    log.debug("Searching database for pattern: {}".format(args.pattern))
    # handle lowercase field input gracefully
    if args.field and args.field in string_fields.keys():
        args.field = string_fields[args.field]

    entries = kp.find_entries(string={args.field: args.pattern}, regex=True, flags=flags)

    for entry in entries:
        print(entry.path)


# process path into parent group and child item
def decompose_path(path):
    if '/' in path.strip('/'):
        [group_path, child_name] = path.strip('/').rsplit('/', 1)
    else:
        group_path = ''
        child_name = path.strip('/')

    log.debug("Decomposed path into: '{}' and '{}'".format(group_path + '/', child_name))
    return [group_path + '/', child_name]


# create new entry/group
def add(args):
    kp = open_database(args)

    [group_path, child_name] = decompose_path(args.path)
    if not child_name:
        log.error(red("Path is invalid"))

    log.debug("args.path:{}".format(args.path))
    log.debug("group_path:{} , child_name:{}".format(group_path, child_name))

    parent_group = kp.find_groups(path=group_path, first=True)

    if parent_group is None:
        log.error(red("No such group ") + bold(group_path))
        return

    # create a new group
    if args.path.endswith('/'):
        kp.add_group(parent_group, child_name)

    # create a new entry
    else:
        username = input(green('Username: '))

        # use urandom for number generation
        rng = random.SystemRandom()
        # generate correct-horse-battery-staple password
        if args.words:
            with open(wordlist_file, 'r') as f:
                wordlist = f.read().splitlines()
                selected = rng.sample(wordlist, args.words)
            password = '.'.join(selected)

        # generate alphanumeric password
        elif args.alphanumeric:
            selected = [rng.choice(alphabetic + numeric) for _ in range(0, args.alphanumeric)]
            password = ''.join(selected)

        # generate alphanumeric + symbolic password
        elif args.symbolic:
            selected = [rng.choice(alphabetic + numeric + symbolic) for _ in range(0, args.symbolic)]
            password = ''.join(selected)

        # prompt for password instead of generating it
        else:
            password = getpass(green('Password: '))
            password_confirm = getpass(green('Confirm: '))
            if not password == password_confirm:
                log.error(red("Passwords do not match"))
                sys.exit()

        url = input(green('URL: '))
        kp.add_entry(parent_group, child_name, username, password, url=url)

    kp.save()


# remove an entry/group
def remove(args):
    kp = open_database(args)

    # remove a group
    if args.path.endswith('/'):
        group = kp.find_groups(path=args.path, first=True)
        if group:
            group.delete()
        else:
            log.error(red("No such group ") + bold(args.path))
            sys.exit()

    # remove an entry
    else:
        entry = kp.find_entries(path=args.path, first=True)
        if entry:
            entry.delete()
        else:
            log.error(red("No such entry ") + bold(args.path))
            sys.exit()

    kp.save()


# move an entry/group
def move(args):
    kp = open_database(args)

    [group_path, child_name] = decompose_path(args.dest_path)
    parent_group = kp.find_groups(path=group_path, first=True)

    # if source path is group
    if args.src_path.endswith('/'):
        src = kp.find_groups(path=args.src_path, first=True)
        if src:
            # if dest path is group
            if args.dest_path.endswith('/'):
                dest = kp.find_groups(path=args.dest_path, first=True)
                if dest:
                    kp.move_group(src, dest)
                else:
                    src.name = child_name
                    kp.move_group(src, parent_group)
            # if dest path is entry
            else:
                log.error(red("Destination must end in '/'"))

        else:
            log.error(red("No such group ") + bold(args.src_path))
    # if source path is entry
    else:
        src = kp.find_entries(path=args.src_path, first=True)
        if src:
            # if dest path is group
            if args.dest_path.endswith('/'):
                dest = kp.find_groups(path=args.dest_path, first=True)
                if dest:
                    kp.move_entry(src, dest)
                    log.debug("Moving entry: {} -> {}".format(src, dest))
                else:
                    log.error(red("No such group ") + bold(args.dest_path))
            # if dest path is entry
            else:
                dest = kp.find_entries(path=args.dest_path, first=True)
                if dest:
                    log.error(red("There is already an entry at ") + bold(args.dest_path))
                else:
                    log.debug("Renaming entry: {} -> {}".format(src.title, child_name))
                    src.title = child_name
                    log.debug("Moving entry: {} -> {}".format(src, parent_group))
                    kp.move_entry(src, parent_group)
        else:
            log.error(red("No such entry ") + bold(args.src_path))

    kp.save()


def main():
    parser = argparse.ArgumentParser(description="Append -h to any command to view its syntax.")
    parser._positionals.title = "commands"

    subparsers = parser.add_subparsers()
    subparsers.dest = 'command'
    subparsers.required = True

    path_help = 'path to entry (e.g. \'foo\') or group (e.g. \'foo/\')'

    # process args for `show` command
    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', metavar='PATH', type=str, help="path to entry")
    show_parser.add_argument('--field', metavar='FIELD', type=str, default=None, help="show the contents of a specific field as plaintext")
    show_parser.set_defaults(func=show)

    # process args for `type` command
    type_parser = subparsers.add_parser('type', help="select entries using dmenu (or similar) and send to keyboard")
    type_parser.add_argument('prog', metavar='PROG', nargs='?', default='dmenu', help="dmenu-like program to call")
    type_parser.add_argument('--tabbed', action='store_true', default=False, help="type both username and password (tab separated)")
    type_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis during selection")
    type_parser.set_defaults(func=type_entries)

    # process args for `add` command
    add_parser = subparsers.add_parser('add', help="add new entry or group")
    add_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    add_parser.add_argument('-w', '--words', metavar='length', type=int, nargs='?', const=6, default=None, help="generate 'correct horse battery staple' style password when creating entry ")
    add_parser.add_argument('-a', '--alphanumeric', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric password")
    add_parser.add_argument('-s', '--symbolic', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric + symbolic password")
    add_parser.set_defaults(func=add)

    # process args for `remove` command
    remove_parser = subparsers.add_parser('remove', aliases=['rm'], help="remove an entry")
    remove_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    remove_parser.set_defaults(func=remove)

    # process args for `move` command
    move_parser = subparsers.add_parser('move', aliases=['mv'], help="move an entry or group")
    move_parser.add_argument('src_path', metavar='SRC_PATH', type=str, help=path_help)
    move_parser.add_argument('dest_path', metavar='DEST_PATH', type=str, help=path_help)
    move_parser.set_defaults(func=move)

    # process args for `list` command
    list_parser = subparsers.add_parser('list', aliases=['ls'], help="list entries in the database")
    list_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis")
    list_parser.set_defaults(func=list_entries)

    # process args for `grep` command
    grep_parser = subparsers.add_parser('grep', help="list entries with fields matching regex pattern")
    grep_parser.add_argument('pattern', metavar='PATTERN', type=str, help="XSLT style regular expression")
    grep_parser.add_argument('--field', metavar='FIELD', type=str, default='.*', help="search entries for a match in a specific field")
    grep_parser.add_argument('-i', action='store_true', default=False, help="case insensitive searching")
    grep_parser.set_defaults(func=grep)

    # process args for `init` command
    init_parser = subparsers.add_parser('init', help="initialize a new database")
    init_parser.set_defaults(func=init_database)

    # optional arguments
    parser.add_argument('--debug', action='store_true', default=False, help="enable debug messages")
    parser.add_argument('--cache', metavar='PATH', type=str, default=passhole_cache, help="specify password cache")
    parser.add_argument('--no-cache', action='store_true', default=False, help="don't cache database password")
    parser.add_argument('--gpgkey', metavar='FINGERPRINT', type=str, default=None, help="specify GPG key to use when caching database password")
    parser.add_argument('--keyfile', metavar='PATH', type=str, default=None, help="specify keyfile path")
    parser.add_argument('--no-keyfile', action='store_true', default=False, help="don't look for a database keyfile or create one")
    parser.add_argument('--no-password', action='store_true', default=False, help="don't prompt for a password")
    parser.add_argument('--database', metavar='PATH', type=str, default=database_file, help="specify database path")
    parser.add_argument('-v', '--version', action='version', version=__version__, help="show version information")

    args = parser.parse_args()

    if args.debug:
        print('Debugging enabled...')
        log.setLevel(logging.DEBUG)

    args.func(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
