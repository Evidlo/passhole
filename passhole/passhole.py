#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Evan Widloski - 2017-03-07
# Passhole - Keepass CLI + dmenu interface

from __future__ import absolute_import
from __future__ import print_function
from builtins import input
from .version import __version__
import subprocess
from getpass import getpass
from colorama import Fore, Back, Style
from base64 import b64encode
from io import BytesIO
import readline
import gpgme
import random
import os
import sys
import shutil
import logging
import argparse


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

gpg = gpgme.Context()

reserved_fields = {
    'username':'UserName',
    'url':'URL',
    'password':'Password',
    'notes':'Notes',
    'title': 'Title'
}


# convenience functions for colored prompts
def red(text):
    return Fore.RED + text + Fore.RESET
def green(text):
    return Fore.GREEN + text + Fore.RESET
def blue(text):
    return Fore.BLUE + text + Fore.RESET
def bold(text):
    return Style.BRIGHT + text + Style.NORMAL

def editable_input(prompt, prefill=None):
    def hook():
        readline.insert_text(prefill)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result

# assertions for entry/group existence/non-existence
def get_group(kp, path):
    group = kp.find_groups(path=path, first=True)
    if group is None:
        log.error(red("No such group ") + bold(path))
        sys.exit()
    return group
def get_entry(kp, path):
    entry = kp.find_entries(path=path, first=True)
    if entry is None:
        log.error(red("No such entry ") + bold(path))
        sys.exit()
    return entry
def get_field(entry, field_input):
    field = reserved_fields.get(field_input, field_input)
    if field not in entry._get_string_field_keys():
        log.error(red("No such field ") + bold(field_input))
        sys.exit()
    return field
def no_entry(kp, path):
    if kp.find_entries(path=path, first=True):
        log.error(red("There is already an entry at ") + bold(path))
        sys.exit()
def no_group(kp, path):
    if kp.find_groups(path=path, first=True):
        log.error(red("There is already group at ") + bold(path))
        sys.exit()


def init_database(args):
    """Create database"""
    from pykeepass.pykeepass import PyKeePass

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

        use_keyfile = editable_input("Would you like to generate a keyfile? (Y/n): ")
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
        kp.password = password
        kp.keyfile = keyfile
        kp.save()
        # create password cache
        if password and not args.no_cache:
            create_password_cache(args.cache, password, args.gpgkey)

    # quit if database already exists
    else:
        log.error(red("Found existing file at ") + bold(args.database))
        sys.exit()


def create_password_cache(cache, password, fingerprint):
    """Cache database password to a gpg encrypted file"""

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
                sys.exit()
        # otherwise get the first key
        else:
            selected_key = keys[0]

    else:
        log.error(
            red("no GPG keys found. Try ") +
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
            log.error(
                red(
                    "Your GPG key is untrusted.  Run " +
                    bold("gpg2 --edit-key \"{}\" trust".format(selected_key.uids[0].name)) +
                    red(" to change the trust level")
                )
            )
            os.remove(cache)
            sys.exit()
        else:
            raise e

    infile.close()


def open_database(
        database=database_file,
        keyfile=keyfile_path,
        cache=passhole_cache,
        no_keyfile=False,
        no_password=False,
        no_cache=False,
        gpgkey=None,
        **kwargs
):
    """Load database

    Parameters
    ----------
    database : str, optional
        path to create database
    keyfile : str, optional
        path to create keyfile
    cache : str, optional
        path to create password cache

    Other Parameters
    ----------------
    no_keyfile : bool, optional
        if True, assume database has no keyfile
    no_password : bool, optional
        if True, assume database has no password
    no_cache : bool, optional
        if True, don't create a password cache
    gpgkey : str, optional
        GPG key fingerprint of GPG key to use when creating cache

    Returns
    -------
    PyKeePass object
    """
    from pykeepass.pykeepass import PyKeePass

    # check if database exists
    if not os.path.exists(database):
        log.error(
            red("No database found at ") +
            bold(database) +
            red(".  Run ") +
            bold("ph init")
        )
        sys.exit()

    # check if keyfile exists, try to use default keyfile
    if no_keyfile:
        keyfile = None
    else:
        if not keyfile:
            if os.path.exists(keyfile_path):
                keyfile = keyfile_path
            else:
                keyfile = None
        else:
            if os.path.exists(keyfile):
                keyfile = keyfile
            else:
                log.error(red("No keyfile found at ") + bold(keyfile))
                sys.exit()

    if no_password:
        password = None
    else:
        # retrieve password from cache
        if os.path.exists(os.path.expanduser(cache)) and not no_cache:
            log.debug("Retrieving password from {}".format(cache))
            outfile = BytesIO()
            with open(cache, 'rb') as infile:
                try:
                    gpg.decrypt(infile, outfile)
                except gpgme.GpgmeError as e:
                    if e.code == gpgme.ERR_DECRYPT_FAILED:
                        log.error(red("Could not decrypt cache"))
                        sys.exit()
                    elif e.code == gpgme.ERR_NO_SECKEY:
                        log.error(
                            red("No GPG secret key found.  Please generate a keypair using ") +
                            bold("gpg2 --full-generate-key")
                        )
                        sys.exit()
                    elif e.code == gpgme.ERR_CANCELED:
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
                log.debug('Detected non-interactive shell')
                NULL = open(os.devnull, 'w')
                try:
                    p = subprocess.Popen(
                        ["zenity", "--entry", "--hide-text", "--text='Enter password'"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.NULL,
                        close_fds=True
                    )
                except FileNotFoundError:
                    log.error(bold("zenity ") + red("not found."))
                    sys.exit()
                password = p.communicate()[0].decode('utf-8').rstrip('\n')

            if password:
                if not no_cache:
                    create_password_cache(cache, password, gpgkey)

            else:
                log.error(red("No password given"))
                sys.exit()

    log.debug("opening {} with password:{} and keyfile:{}".format(
        database,
        str(password),
        str(keyfile)
    ))
    try:
        kp = PyKeePass(database, password=password, keyfile=keyfile)
    except IOError:
        log.error(red("Password or keyfile incorrect"))
        if os.path.exists(os.path.expanduser(cache)) and not no_cache:
            log.error(red("Try clearing the cache at ") + bold(cache))
        sys.exit()
    return kp


def type_entries(args):
    """Type out password using keyboard

    Selects an entry using `prog`, then sends the password to the keyboard.
    If `tabbed` is true, both the username and password are typed, separated
    by a tab"""

    from pynput.keyboard import Controller, Key

    kp = open_database(**vars(args))

    entry_paths = [entry.path for entry in kp.entries if entry.title]
    entry_texts = []
    for entry in kp.entries:
        if args.username:
            entry_texts.append("{} ({})".format(str(entry.path), str(entry.username)))
        else:
            entry_texts.append("{}".format(str(entry.path)))

    items = '\n'.join(sorted(entry_texts))

    # get the entry from dmenu
    try:
        p = subprocess.Popen(
            args.prog.split(' '),
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
    except FileNotFoundError:
        log.error(bold(args.prog[0]) + red(" not found."))
        sys.exit()
    stdout = p.communicate(input=items.encode('utf-8'))[0].decode('utf-8')
    selection_path = stdout.rstrip('\n').lstrip('[').rstrip(']')

    # if nothing was selected, return None
    if not selection_path:
        log.warning("No path returned by {}".format(args.prog))
        return

    selected_entry = get_entry(kp, selection_path)

    log.debug("selected_entry:{}".format(selected_entry))

    def call_xdotool(args):
        try:
            subprocess.call(["xdotool"] + args)
        except FileNotFoundError:
            log.error(bold("xdotool ") + red("not found"))
            sys.exit()

    # type out password
    k = Controller()
    if args.tabbed:
        if selected_entry.username:
            if args.xdotool:
                call_xdotool(['type', selected_entry.username])
                call_xdotool(['key', 'Tab'])
            else:
                k.type(selected_entry.username)
                k.press(Key.tab)
                k.release(Key.tab)
        else:
            log.warning("Selected entry does not have a username")
    if selected_entry.password:
        if args.xdotool:
            call_xdotool(['type', selected_entry.password])
        else:
            k.type(selected_entry.password)
    else:
        log.warning("Selected entry does not have a password")


def show(args):
    """Print out the contents of an entry to console"""

    kp = open_database(**vars(args))

    entry = get_entry(kp, args.entry_path)
    # show specified field
    if args.field:
        # handle lowercase field input gracefully
        field = get_field(entry, args.field)
        print(entry._get_string_field(field), end='')

    # otherwise, show all fields
    else:
        print(green("Title: ") + (entry.title or ''))
        print(green("Username: ") + (entry.username or ''))
        print(
            green("Password: ") + Fore.RED + Back.RED +
            (entry.password or '') +
            Fore.RESET + Back.RESET
        )
        print(green("URL: ") + (entry.url or ''))
        for field_name, field_value in entry.custom_properties.items():
            print(green("{}: ".format(field_name)) + str(field_value or ''))


def list_entries(args):
    """List Entries/Groups in the database as a tree"""

    kp = open_database(**vars(args))

    # recursive function to list items in a group
    def list_items(group, prefix, show_branches=True):
        branch_corner = "└── " if show_branches else ""
        branch_tee = "├── " if show_branches else ""
        branch_pipe = "│   " if show_branches else ""
        branch_blank = "    " if show_branches else ""
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

    if args.path.endswith('/'):
        list_items(get_group(kp, args.path), "", show_branches=False)
    else:
        entry = get_entry(kp, args.path)
        if args.username:
            entry_string = "{} ({})".format(str(entry.title), str(entry.username))
        else:
            entry_string = "{}".format(str(entry.title))
        print(entry_string)


def grep(args):
    """Search all string fields for a string"""

    kp = open_database(**vars(args))

    flags = 'i' if args.i else None
    log.debug("Searching database for pattern: {}".format(args.pattern))

    if args.field:
        # handle lowercase field input gracefully
        args.field = reserved_fields.get(args.field, args.field)
    else:
        args.field = 'Title'

    entries = kp.find_entries(string={args.field: args.pattern}, regex=True, flags=flags)

    for entry in entries:
        print(entry.path)


def decompose_path(path):
    """Process path into parent group and child item"""

    if '/' in path.strip('/'):
        [group_path, child_name] = path.strip('/').rsplit('/', 1)
    else:
        group_path = ''
        child_name = path.strip('/')

    log.debug("Decomposed path into: '{}' and '{}'".format(group_path + '/', child_name))
    return [group_path + '/', child_name]


def add(args):
    """Create new entry/group"""

    kp = open_database(**vars(args))

    [group_path, child_name] = decompose_path(args.path)
    if not child_name:
        log.error(red("Path is invalid"))
        sys.exit()

    log.debug("args.path:{}".format(args.path))
    log.debug("group_path:{} , child_name:{}".format(group_path, child_name))

    parent_group = get_group(kp, group_path)

    # create a new group
    if args.path.endswith('/'):
        no_group(kp, args.path)
        kp.add_group(parent_group, child_name)

    # create a new entry
    else:
        no_entry(kp, args.path)
        username = editable_input(green('Username: '))

        # use urandom for number generation
        rng = random.SystemRandom()
        # generate correct-horse-battery-staple password
        if args.words:
            with open(wordlist_file, 'r') as f:
                wordlist = f.read().splitlines()
                selected = rng.sample(wordlist, args.words)
            password = ' '.join(selected)

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

        # append fixed string to password
        if args.append:
            password += args.append

        url = editable_input(green('URL: '))
        kp.add_entry(parent_group, child_name, username, password, url=url)

    kp.save()


def remove(args):
    """Remove an Entry/Group"""

    kp = open_database(**vars(args))

    # remove a group
    if args.path.endswith('/'):
        group = get_group(kp, args.path)
        if len(group.entries) > 0:
            log.error(red("Non-empty group ") + bold(args.path))
            sys.exit()
        group.delete()

    # remove an entry
    else:
        entry = get_entry(kp, args.path)
        entry.delete()

    kp.save()


def edit(args):
    """Edit fields of an Entry"""

    kp = open_database(**vars(args))

    entry = get_entry(kp, args.entry_path)

    # edit specific field
    if args.field:
        field = get_field(entry, args.field)
        value = editable_input(
            green("{}: ".format(field)),
            entry._get_string_field(field)
        )
        entry._set_string_field(field, value)
    # add/set a field
    elif args.set:
        field = reserved_fields.get(args.set[0], args.set[0])
        entry._set_string_field(field, args.set[1])
    # remove a field
    elif args.remove:
        field = get_field(entry, args.remove)
        results = entry._element.xpath('String/Key[text()="{}"]/..'.format(field))
        entry._element.remove(results[0])
    # otherwise, edit all fields
    else:
        for field in entry._get_string_field_keys():
            value = editable_input(
                green("{}: ".format(field)),
                entry._get_string_field(field)
            )
            entry._set_string_field(field, value)

    kp.save()


def move(args):
    """Move an Entry/Group"""

    kp = open_database(**vars(args))

    [group_path, child_name] = decompose_path(args.dest_path)
    parent_group = kp.find_groups(path=group_path, first=True)

    # if source path is group
    if args.src_path.endswith('/'):
        src = get_group(kp, args.src_path)
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
            sys.exit()
    # if source path is entry
    else:
        src = get_entry(kp, args.src_path)
        # if dest path is group
        if args.dest_path.endswith('/'):
            dest = get_group(kp, args.dest_path)
            kp.move_entry(src, dest)
            log.debug("Moving entry: {} -> {}".format(src, dest))
        # if dest path is entry
        else:
            no_entry(kp, args.dest_path)
            log.debug("Renaming entry: {} -> {}".format(src.title, child_name))
            src.title = child_name
            log.debug("Moving entry: {} -> {}".format(src, parent_group))
            kp.move_entry(src, parent_group)

    kp.save()


def dump(args):
    """Pretty print database XML to console"""

    from lxml import etree

    kp = open_database(**vars(args))

    print(
        etree.tostring(
            kp.tree,
            pretty_print=True,
            standalone=True,
            encoding='utf-8'
        ).decode('utf-8')
    )


def create_parser():
    """Create argparse object"""

    parser = argparse.ArgumentParser(description="Append -h to any command to view its syntax.")
    parser._positionals.title = "commands"

    subparsers = parser.add_subparsers()
    subparsers.dest = 'command'
    subparsers.required = True

    path_help = "entry path (e.g. 'foo') or group path (e.g. 'foo/')"

    # process args for `show` command
    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('entry_path', metavar='PATH', type=str, help="path to entry")
    show_parser.add_argument('--field', metavar='FIELD', type=str, default=None, help="show the contents of a specific field")
    show_parser.set_defaults(func=show)

    # process args for `type` command
    type_parser = subparsers.add_parser('type', help="select entries using dmenu (or similar) and send to keyboard")
    type_parser.add_argument('prog', metavar='PROG', nargs='?', default='dmenu', help="dmenu-like program to call")
    type_parser.add_argument('--tabbed', action='store_true', default=False, help="type both username and password (tab separated)")
    type_parser.add_argument('--xdotool', action='store_true', default=False, help="use xdotool for typing passwords")
    type_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis during selection")
    type_parser.set_defaults(func=type_entries)

    # process args for `add` command
    add_parser = subparsers.add_parser('add', help="add new entry or group")
    add_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    add_parser.add_argument('-w', '--words', metavar='length', type=int, nargs='?', const=6, default=None, help="generate 'correct horse battery staple' style password when creating entry ")
    add_parser.add_argument('-a', '--alphanumeric', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric password")
    add_parser.add_argument('-s', '--symbolic', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric + symbolic password")
    add_parser.add_argument('--append', metavar='STR', type=str, help="append string to generated password")
    add_parser.set_defaults(func=add)

    # process args for `remove` command
    remove_parser = subparsers.add_parser('remove', aliases=['rm'], help="remove an entry")
    remove_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    remove_parser.set_defaults(func=remove)

    # process args for `edit` command
    edit_parser = subparsers.add_parser('edit', help="edit the contents of an entry")
    edit_parser.add_argument('entry_path', metavar='PATH', type=str, help="path to entry")
    edit_parser.add_argument('--field', metavar='FIELD', type=str, default=None, help="edit the contents of a specific field")
    edit_parser.add_argument('--set', metavar=('FIELD', 'VALUE'), type=str, nargs=2, default=None, help="add/edit the contents of a specific field, noninteractively")
    edit_parser.add_argument('--remove', metavar='FIELD', type=str, default=None, help="remove a field from the entry")
    edit_parser.set_defaults(func=edit)

    # process args for `move` command
    move_parser = subparsers.add_parser('move', aliases=['mv'], help="move an entry or group")
    move_parser.add_argument('src_path', metavar='SRC_PATH', type=str, help=path_help)
    move_parser.add_argument('dest_path', metavar='DEST_PATH', type=str, help=path_help)
    move_parser.set_defaults(func=move)

    # process args for `list` command
    list_parser = subparsers.add_parser('list', aliases=['ls'], help="list entries in the database")
    list_parser.add_argument('path', nargs='?', metavar='PATH', default='/', type=str, help=path_help)
    list_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis")
    list_parser.set_defaults(func=list_entries)

    # process args for `grep` command
    grep_parser = subparsers.add_parser('grep', help="list entries with title matching regex pattern")
    grep_parser.add_argument('pattern', metavar='PATTERN', type=str, help="XSLT style regular expression")
    #FIXME - default='.*' doesn't work anymore for some reason
    grep_parser.add_argument('--field', metavar='FIELD', type=str, help="search entries for a match in a specific field")
    grep_parser.add_argument('-i', action='store_true', default=False, help="case insensitive searching")
    grep_parser.set_defaults(func=grep)

    # process args for `init` command
    init_parser = subparsers.add_parser('init', help="initialize a new database")
    init_parser.set_defaults(func=init_database)

    # process args for `dump` command
    dump_parser = subparsers.add_parser('dump', help="pretty print database XML to console")
    dump_parser.set_defaults(func=dump)

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

    return parser


def main():

    parser = create_parser()
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
