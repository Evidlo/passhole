#!/bin/env python
## Jack Cottom, Evan Widloski - 2017-03-07
## Passhole - Keepass CLI + dmenu interface


from pykeepass import PyKeePass
from subprocess import Popen, PIPE, STDOUT # for talking to dmenu programs
from pykeyboard import PyKeyboard          # for sending password to keyboard
import random
import os
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

password_file = os.path.expanduser('~/.passhole.kdbx')

wordlist = 'wordlist.10000'                # taken from http://www.mit.edu/~ecprice/wordlist.10000
# load database
if os.path.exists(password_file):
    kp = PyKeePass(password_file, password='shatpass')
else:
    logging("No database file found at {0}".format(password_file))

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
def dmenu(prog, tabbed=False):
    entry_titles = '\n'.join([entry.title for entry in kp.entries])

    # get the entry from dmenu
    p = Popen(prog, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    grep_stdout = p.communicate(input=entry_titles)[0]
    entry_title = grep_stdout.decode().rstrip('\n')
    print(entry_title)
    print(type(entry_title))
    entry = kp.find_entries_by_title(entry_title)[0]

    # type out password
    k = PyKeyboard()
    if tabbed:
        k.type_string(entry.username)
        k.tap_key(k.tab_key)
    k.type_string(entry.password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--dmenu', metavar='PROG', help="select passwords using dmenu (or any program that supports dmenu style line-separated input)")
    parser.add_argument('--tabbed', action='store_true', default=False, help="type out username and password (tab separated) when using --dmenu")
    parser.add_argument('--generate', action='store_true', help="generate 'correct horse battery staple' style password (https://xkcd.com/936/)")

    args = parser.parse_args()

    if args.dmenu:
        dmenu(args.dmenu, args.tabbed)

    if args.generate:
        print(word_sequence(5))




