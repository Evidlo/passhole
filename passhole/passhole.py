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
# import gpgme
import random
import os
from os.path import realpath, expanduser, dirname, join
import sys
import shutil
import logging
import argparse
from configparser import ConfigParser
from collections import OrderedDict


logging.basicConfig(level=logging.ERROR, format='%(message)s')
# hide INFO messages from pykeepass
logging.getLogger("pykeepass").setLevel(logging.WARNING)
log = logging.getLogger(__name__)

default_config = expanduser('~/.config/passhole.ini')
default_database = expanduser('~/.local/passhole/{}.kdbx')
default_keyfile = expanduser('~/.local/passhole/{}.key')

base_dir = dirname(realpath(__file__))
# taken from https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
wordlist_file = join(base_dir, 'wordlist.txt')
template_database_file = join(base_dir, 'blank.kdbx')
template_config_file = join(base_dir, 'passhole.ini')

alphabetic = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
numeric = '0123456789'
symbolic = '!@#$%^&*()_+-=[]{};:'"<>,./?\|`~"

# gpg = gpgme.Context()

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
    result = input(green(prompt + ': '))
    readline.set_pre_input_hook()
    return result
def boolean_input(prompt, default=True):
    result = editable_input(
        prompt + ' (Y/n)' if default else prompt + ' (y/N)'
    )
    if result.lower() == 'y':
        return True
    elif result.lower() == 'n':
        return False
    elif result == '':
        return default
    else:
        # ask again
        return boolean_input(prompt, default)

# assertions for entry/group existence/non-existence
def get_group(kp, path):
    _, path = split_db_prefix(path)
    group = kp.find_groups(path=path, first=True)
    if group is None:
        log.error(red("No such group ") + bold(path))
        sys.exit()
    return group
def get_entry(kp, path):
    _, path = split_db_prefix(path)
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
def split_db_prefix(path):
    if path.startswith('@'):
        if '/' in path:
            return path.lstrip('@').split('/', 1)
        else:
            # return path.lstrip('@'), ''
            return path.lstrip('@'), None
    else:
        return None, path
# def join_db_prefix(prefix, path):
#     if prefix is None:
#         return path
#     else:
#         return '@{}/{}'.format(prefix, path)


def init_database(args):
    """Create database"""
    # from pykeepass.pykeepass import PyKeePass

    # ----- setup config -----

    c = ConfigParser()
    if os.path.exists(args.config):
        c.read(args.config)

    if args.name is None:
        database_name = editable_input("Database name (no spaces)", "passhole")
    else:
        database_name = args.name

    if database_name in c.sections():
        log.error(
            red("There is already a database named ") + bold(database_name) +
            red(" in ") + bold(args.config)
        )
        sys.exit()
    else:
        c.add_section(database_name)

    if not os.path.exists(args.config):
        c.set(database_name, 'default', 'True')

    # ----- database prompt -----

    if args.database is None:
        database_path = editable_input(
            "Desired database path",
            default_database.format(database_name)
        )
    else:
        database_path = args.database

    # quit if database already exists
    if os.path.exists(database_path):
        log.error(red("Found database at ") + bold(database_path))
        sys.exit()
    else:
        c.set(database_name, 'database', database_path)

    # ----- password prompt -----

    if args.no_password:
        password = None
        c.set(database_name, 'no-password', 'True')
    else:
        use_password = boolean_input("Password protect database?")
        if use_password:
            password = getpass(green('Password: '))
            password_confirm = getpass(green('Confirm: '))

            if not password == password_confirm:
                log.error(red("Passwords do not match"))
                sys.exit()
        else:
            password = None
            c.set(database_name, 'no-password', 'True')

    # ----- keyfile prompt -----

    if args.keyfile is None:
        use_keyfile = boolean_input("Use a keyfile?")
        if use_keyfile:
            keyfile = editable_input("Desired keyfile path",
                default_keyfile.format(database_name)
            )
            c.set(database_name, 'keyfile', keyfile)
        else:
            keyfile = None
    else:
        keyfile = args.keyfile
        c.set(database_name, 'keyfile', keyfile)

    # ----- create keyfile/database/config -----
    # create keyfile
    if keyfile is not None:

        log.debug("Looking for keyfile at {}".format(keyfile))
        if os.path.exists(keyfile):
            print("Found existing keyfile at {}  Exiting".format(bold(keyfile)))
            sys.exit()

        print("Creating keyfile at " + bold(keyfile))
        os.makedirs(dirname(keyfile), exist_ok=True)
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
    print("Creating database at {}".format(bold(database_path)))
    os.makedirs(dirname(database_path), exist_ok=True)
    shutil.copy(template_database_file, database_path)

    from pykeepass import PyKeePass
    kp = PyKeePass(database_path, password='password')
    kp.password = password
    kp.keyfile = keyfile
    kp.save()

    # create config
    print("Creating config at {}".format(bold(args.config)))
    os.makedirs(dirname(args.config), exist_ok=True)
    with open(args.config, 'w') as f:
        c.write(f)


def open_database(
        keyfile=None,
        no_cache=False,
        cache_timeout=600,
        no_password=False,
        config=default_config,
        database=None,
        all=False,
        name=None,
        path=None,
        **kwargs
):
    """Load one or more databases

    Parameters
    ----------
    keyfile : str, optional
        path to keyfile.  if not given, assume database has no keyfile
        (default: None)
    no_cache : bool, optional
        don't read/cache database background thread (default: False)
    cache_timeout : int, optional
        seconds to keep read/cache database background thread, has no effect if no_cache=True
        (default: 300)
    no_password : bool, optional
        assume database has no password (default: False)
    config : str
        path to database config. no effect if `database` is not None.
        (default: ~/.config/passhole.ini)
    database : str, optional
        open database at this path and ignore config file if given
        (default: None).  overrides all below options
    all : bool, optional
        return a list of 2-tuples containing all databases in the config
        (default: False).  overrides all below options
    name : str, optional
        section name in config of database to open (default: None)
        overrides all below options
    path : str, optional
        entry or group path.  the '@' prefix will be used to determine
        which database in the config to open (default: None)

    Returns
    -------
    PyKeePass object or list of (name, PyKeePass) tuples
    """

    from pykeepass_cache.pykeepass_cache import PyKeePass, cached_databases

    def prompt_open(name, database, keyfile, no_password, no_cache, cache_timeout):
        """Open a database and return KeePass object"""
        cache_timeout = int(cache_timeout)

        if database is not None:
            database = realpath(expanduser(database))
        if keyfile is not None:
            keyfile = realpath(expanduser(keyfile))

        # check if database exists
        if not os.path.exists(database):
            log.error(
                red("No database found at ") +
                bold(database)
            )
            sys.exit()

        if not no_cache:
            opened_databases = cached_databases(timeout=cache_timeout)
            log.debug("opened databases:" + str(opened_databases))
            # if database is already open on server
            if database in opened_databases:
                log.debug("opening {} from cache".format(database))
                return opened_databases[database]

        log.debug("{} not found in cache".format(database))
        # if path of given keyfile doesn't exist
        if keyfile is not None and  not os.path.exists(keyfile):
            log.error(red("No keyfile found at ") + bold(keyfile))
            sys.exit()

        if no_password:
            password = None
        else:
            if name is not None:
                prompt = 'Enter database password ({}):'.format(name)
            else:
                prompt = 'Enter database password:'

            # check if running in interactive shell
            if os.isatty(sys.stdout.fileno()):
                password = getpass('{} '.format(prompt))

            # otherwise use zenity
            else:
                log.debug('Detected non-interactive shell')
                try:
                    p = subprocess.Popen(
                        ["zenity", "--entry", "--hide-text", "--text='{}'".format(prompt)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=open(os.devnull, 'w'),
                        close_fds=True
                    )
                except FileNotFoundError:
                    log.error(bold("zenity ") + red("not found."))
                    sys.exit()
                password = p.communicate()[0].decode('utf-8').rstrip('\n')

        log.debug("opening {} with password:{} and keyfile:{}".format(
            database,
            None if password is None else 'redacted',
            str(keyfile)
        ))

        if no_cache:
            from pykeepass import PyKeePass as PyKeePass_nocache
            return PyKeePass_nocache(database, password=password, keyfile=keyfile)
        else:
            return PyKeePass(database, password=password, keyfile=keyfile, timeout=cache_timeout)


    # if 'database' argument given, ignore config completely
    if database is not None:
        kp = prompt_open(database, database, keyfile, no_password, no_cache, cache_timeout)
        if all:
            return [(None, kp)]
        else:
            return kp
    else:

        # read config
        if not os.path.exists(config):
            log.error(red("No config found at ") + bold(config))
            sys.exit()

        c = ConfigParser()
        log.debug("reading config from {}".format(config))
        c.read(config)

        # find default section
        for section in c.sections():
            if c.has_option(section, 'default') and c[section].getboolean('default'):
                default_section = section
                log.debug('default_section {}'.format(default_section))
                break
        else:
            default_section = None

        # validate that every section has 'database'
        for s in c.sections():
            if not c.has_option(s, 'database'):
                log.error(bold('database') + red(' option is required'))
                sys.exit()

        # open all databases in config
        if all:
            kps = []
            for section in c.sections():
                kp = prompt_open(
                    section,
                    c[section].get('database'),
                    c[section].get('keyfile'),
                    c[section].get('no-password'),
                    c[section].get('no-cache', no_cache),
                    c[section].get('cache-timeout', cache_timeout)
                )

                # set default database to be first
                if section == default_section:
                    kps.insert(0, (section, kp))
                else:
                    kps.append((section, kp))
            return kps

        # open a specific database in config by name
        elif name is not None:
            if name not in c.sections():
                log.error(red("No config section found for " + bold(section)))
                sys.exit()
            return prompt_open(
                name,
                c[name]['database'],
                c[name].get('keyfile'),
                c[name].get('no-password'),
                c[name].get('no-cache', no_cache),
                c[name].get('cache-timeout', cache_timeout)
            )

        # open a specific database in config using full Element path
        elif path is not None:
            section, _ = split_db_prefix(path)
            if section is None:
                if default_section is None:
                    log.error(red("No default database specified in config"))
                    sys.exit()
                return prompt_open(
                    section,
                    c[default_section].get('database'),
                    c[default_section].get('keyfile'),
                    c[default_section].get('no-password'),
                    c[default_section].get('no-cache', no_cache),
                    c[default_section].get('cache-timeout', cache_timeout)
                )
            if section not in c.sections():
                log.error(red("No config section found for " + bold(section)))
                sys.exit()
            return prompt_open(
                section,
                c[section].get('database'),
                c[section].get('keyfile'),
                c[section].get('no-password'),
                c[section].get('no-cache', no_cache),
                c[section].get('cache-timeout', cache_timeout)
            )

        # open default database in config
        if default_section is None:
            log.error(red("No default database specified in config"))
            sys.exit()
        return prompt_open(
            section,
            c[default_section].get('database'),
            c[default_section].get('keyfile'),
            c[default_section].get('no-password'),
            c[default_section].get('no-cache', no_cache),
            c[default_section].get('cache-timeout', cache_timeout)
        )


def type_entries(args):
    """Type out password using keyboard

    Selects an entry using `prog`, then sends the password to the keyboard.
    If `tabbed` is true, both the username and password are typed, separated
    by a tab"""

    from Xlib.error import DisplayNameError

    try:
        from pynput.keyboard import Controller, Key
    except DisplayNameError:
        log.error(red("No X11 session found"))

    entry_texts = {}

    # type from all databases
    if args.name is None:
        databases = open_database(all=True, **vars(args))

        # generate multi-line string to send to dmenu
        for name, kp in databases:
            for entry in kp.entries:
                if entry.title:
                    if len(databases) > 1:
                        entry_text = "@{}/{}".format(name, entry.path)
                    else:
                        entry_text = entry.path
                    if args.username:
                        entry_text += " ({})".format(entry.username)
                    entry_texts[entry_text] = kp
        dmenu_text = '\n'.join(sorted(entry_texts.keys()))

    # type from specific database
    else:
        kp = open_database(**vars(args))
        for entry in kp.entries:
            if entry.title:
                entry_text = entry.path
                if args.username:
                    entry_text += " ({})".format(entry.username)
                entry_texts[entry_text] = kp
        dmenu_text = '\n'.join(sorted(entry_texts.keys()))


    # get the entry from dmenu
    try:
        p = subprocess.Popen(
            args.prog,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True
        )
    except FileNotFoundError:
        log.error(bold(args.prog[0]) + red(" not found."))
        sys.exit()
    stdout = p.communicate(input=dmenu_text.encode('utf-8'))[0].decode('utf-8').rstrip('\n')
    log.debug("text from dmenu: {}".format(stdout))

    # if nothing was selected, return None
    if not stdout:
        log.warning("No path returned by {}".format(args.prog))
        return

    kp = entry_texts[stdout]
    _, selection_path = split_db_prefix(stdout)
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

    entry = get_entry(kp, args.path)
    # show specified field
    if args.field:
        # handle lowercase field input gracefully
        field = get_field(entry, args.field)
        print(entry._get_string_field(field), end='')

    # otherwise, show all fields
    else:
        print(green("Title: ") + (entry.title or ''))
        print(green("UserName: ") + (entry.username or ''))
        print(
            green("Password: ") + Fore.RED + Back.RED +
            (entry.password or '') +
            Fore.RESET + Back.RESET
        )
        print(green("URL: ") + (entry.url or ''))
        for field_name, field_value in entry.custom_properties.items():
            print(green("{}: ".format(field_name)) + str(field_value or ''))
        print(green("Created: ") + entry.ctime.isoformat())
        print(green("Modified: ") + entry.mtime.isoformat())


def list_entries(args):
    """List Entries/Groups in the database as a tree"""

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

    # print all databases
    if args.path is None:
        databases = open_database(all=True, **vars(args))
        for position, (name, kp) in enumerate(databases):
            # print names for config-provided databases
            if len(databases) > 1:
                print('{}{}{}'.format(
                    '' if position == 0 else '\n',
                    bold(green('@' + name)),
                    ' (default)' if position == 0 else ''
                ))
            list_items(kp.root_group, "", show_branches=False)

    # print specific database
    else:
        kp = open_database(**vars(args))
        # FIXME: write a function: parse_path -> type (db, group, entry)
        # if group, list items
        if args.path.endswith('/'):
            list_items(get_group(kp, args.path), "", show_branches=False)
        # if db, list items in root group
        elif args.path.startswith('@') and '/' not in args.path:
            list_items(kp.root_group, "", show_branches=False)
        # if entry, print entry contents
        else:
            args.field = None
            show(args)


def grep(args):
    """Search all string fields for a string"""

    databases = open_database(all=True, **vars(args))

    for position, (name, kp) in enumerate(databases):
        flags = 'i' if args.i else None
        log.debug("Searching database for pattern: {}".format(args.pattern))

        if args.field:
            # handle lowercase field input gracefully
            args.field = reserved_fields.get(args.field, args.field)
        else:
            args.field = 'Title'

        entries = kp.find_entries(string={args.field: args.pattern}, regex=True, flags=flags)

        # print names for config-provided databases
        if len(databases) > 1 and len(entries) > 0:
            print('{}[{}]{}'.format(
                '' if position == 0 else '\n',
                bold(green(name)),
                ' (default)' if position == 0 else ''
            ))
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
        username = editable_input('Username')

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

        url = editable_input('URL')

        # log.debug(
        #     'Adding entry: group:{}, title:{}, user:{}, pass:{}, url:{}'.format(
        #         parent_group, child_name, username, password, url
        #     )
        # )
        entry = kp.add_entry(parent_group, child_name, username, password, url=url)

        # set custom fields
        if args.fields is not None:
            for field in args.fields.split(','):
                # capitalize reserved fields
                field = reserved_fields.get(field, field).strip()
                value = editable_input(field)
                entry._set_string_field(field, value)
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

    # edit group name
    if args.path.endswith('/'):
        group = get_group(kp, args.path)

        if args.set:
            field = args.set[0]
            if field.lower() != 'name':
                log.error(red("Only 'name' is supported for Group FIELD"))
                sys.exit()
            group.name = args.set[1]

        # otherwise, edit interactively
        else:
            value = editable_input('Name', group.name)
            group.name = value

    else:
        entry = get_entry(kp, args.path)

        # edit specific field
        if args.field:
            field = get_field(entry, args.field)
            value = editable_input(field, entry._get_string_field(field))
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

        # otherwise, edit all fields interactively
        else:
            for field in entry._get_string_field_keys():
                value = editable_input(field, entry._get_string_field(field))
                entry._set_string_field(field, value)

    kp.save()


def move(args):
    """Move an Entry/Group"""

    src_kp = open_database(path=args.src_path, **vars(args))
    dest_kp = open_database(path=args.dest_path, **vars(args))

    # FIXME: pykeepass_cache doesn't support moving elements between databases
    if src_kp.filename != dest_kp.filename:
        log.error(red("Moving elements between databases not supported"))
        sys.exit()

    [group_path, child_name] = decompose_path(args.dest_path)
    # parent_group = get_group(dest_kp, group_path)
    parent_group = get_group(src_kp, group_path)

    # if source path is group
    if args.src_path.endswith('/'):
        src = get_group(src_kp, args.src_path)

        # if dest path is group
        if args.dest_path.endswith('/'):
            # dest = dest_kp.find_groups(path=args.dest_path, first=True)
            dest = src_kp.find_groups(path=args.dest_path, first=True)
            if dest:
                # dest_kp.move_group(src, dest)
                src_kp.move_group(src, dest)
            else:
                src.name = child_name
                # dest_kp.move_group(src, parent_group)
                src_kp.move_group(src, parent_group)

        # if dest path is entry
        else:
            log.error(red("Destination must end in '/'"))
            sys.exit()

    # if source path is entry
    else:
        src = get_entry(src_kp, args.src_path)

        # if dest path is group
        if args.dest_path.endswith('/'):
            # dest = get_group(dest_kp, args.dest_path)
            dest = get_group(src_kp, args.dest_path)
            # dest_kp.move_entry(src, dest)
            src_kp.move_entry(src, dest)
            log.debug("Moving entry: {} -> {}".format(src, dest))

        # if dest path is entry
        else:
            # no_entry(dest_kp, args.dest_path)
            no_entry(src_kp, args.dest_path)
            log.debug("Renaming entry: {} -> {}".format(src.title, child_name))
            src.title = child_name
            log.debug("Moving entry: {} -> {}".format(src, parent_group))
            # dest_kp.move_entry(src, parent_group)
            src_kp.move_entry(src, parent_group)

    src_kp.save()
    # dest_kp.save()


def dump(args):
    """Pretty print database XML to console"""

    from lxml import etree

    kp = open_database(**vars(args))

    print(kp.xml())


def create_parser():
    """Create argparse object"""

    parser = argparse.ArgumentParser(description="Append -h to any command to view its syntax.")
    parser._positionals.title = "commands"

    subparsers = parser.add_subparsers()
    subparsers.dest = 'command'
    subparsers.required = True

    path_help = "entry path (e.g. 'foo') or group path (e.g. 'foo/')"

    # process args for `list` command
    list_parser = subparsers.add_parser('list', aliases=['ls'], help="list entries in the database")
    list_parser.add_argument('path', nargs='?', metavar='PATH', default=None, type=str, help=path_help)
    list_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis")
    list_parser.set_defaults(func=list_entries)

    # process args for `add` command
    add_parser = subparsers.add_parser('add', help="add new entry or group")
    add_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    add_parser.add_argument('-w', '--words', metavar='length', type=int, nargs='?', const=6, default=None, help="generate 'correct horse battery staple' style password when creating entry ")
    add_parser.add_argument('-a', '--alphanumeric', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric password")
    add_parser.add_argument('-s', '--symbolic', metavar='length', type=int, nargs='?', const=16, default=None, help="generate alphanumeric + symbolic password")
    add_parser.add_argument('--append', metavar='STR', type=str, help="append string to generated password")
    add_parser.add_argument('--fields', metavar='FIELD1,...', type=str, help="comma separated list of custom fields")
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

    # process args for `show` command
    show_parser = subparsers.add_parser('show', help="show the contents of an entry")
    show_parser.add_argument('path', metavar='PATH', type=str, help="path to entry")
    show_parser.add_argument('--field', metavar='FIELD', type=str, default=None, help="show the contents of a specific field")
    show_parser.set_defaults(func=show)

    # process args for `edit` command
    edit_parser = subparsers.add_parser('edit', help="edit the contents of an entry or group")
    edit_parser.add_argument('path', metavar='PATH', type=str, help=path_help)
    edit_parser.add_argument('--field', metavar='FIELD', type=str, default=None, help="edit the contents of a specific field")
    edit_parser.add_argument('--set', metavar=('FIELD', 'VALUE'), type=str, nargs=2, default=None, help="add/edit the contents of a specific field, noninteractively")
    edit_parser.add_argument('--remove', metavar='FIELD', type=str, default=None, help="remove a field from the entry")
    edit_parser.set_defaults(func=edit)

    # process args for `type` command
    type_parser = subparsers.add_parser('type', help="select entries using dmenu (or similar) and send to keyboard")
    type_parser.add_argument('name', type=str, nargs='?', default=None, help="name of database to type from")
    type_parser.add_argument('--prog', metavar='PROG', default='dmenu', help="dmenu-like program to call")
    type_parser.add_argument('--tabbed', action='store_true', default=False, help="type both username and password (tab separated)")
    type_parser.add_argument('--xdotool', action='store_true', default=False, help="use xdotool for typing passwords")
    type_parser.add_argument('--username', action='store_true', default=False, help="show username in parenthesis during selection")
    type_parser.set_defaults(func=type_entries)

    # process args for `init` command
    init_parser = subparsers.add_parser('init', help="initialize a new database")
    init_parser.add_argument('--name', type=str, help="name of database to initialize")
    init_parser.set_defaults(func=init_database)

    # process args for `grep` command
    grep_parser = subparsers.add_parser('grep', help="list entries with title matching regex pattern")
    grep_parser.add_argument('pattern', metavar='PATTERN', type=str, help="XSLT style regular expression")
    #FIXME - default='.*' doesn't work anymore for some reason
    grep_parser.add_argument('--field', metavar='FIELD', type=str, help="search entries for a match in a specific field")
    grep_parser.add_argument('-i', action='store_true', default=False, help="case insensitive searching")
    grep_parser.set_defaults(func=grep)

    # process args for `dump` command
    dump_parser = subparsers.add_parser('dump', help="pretty print database XML to console")
    dump_parser.add_argument('name', type=str, nargs='?', default=None, help="name of database to dump")
    dump_parser.set_defaults(func=dump)

    # optional arguments
    parser.add_argument('--debug', action='store_true', default=False, help="enable debug messages")
    parser.add_argument('--database', metavar='PATH', type=str, help="specify database path")
    parser.add_argument('--keyfile', metavar='PATH', type=str, default=None, help="specify keyfile path")
    parser.add_argument('--no-password', action='store_true', default=False, help="don't prompt for a password")
    parser.add_argument('--no-cache', action='store_true', default=False, help="don't cache this database in a background process")
    parser.add_argument('--cache-timeout', metavar='SEC', type=int, default=600, help="seconds to hold database open in a background process")
    parser.add_argument('--config', metavar='PATH', type=str, default=default_config, help="specify config path")
    parser.add_argument('-v', '--version', action='version', version=__version__, help="show version information")

    return parser


def main():

    parser = create_parser()
    args = parser.parse_args()

    if args.debug:
        print('Debugging enabled...')
        log.setLevel(logging.DEBUG)
        logging.getLogger('pykeepass_cache').setLevel(logging.DEBUG)

    args.func(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
