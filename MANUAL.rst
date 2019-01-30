=========
passhole
=========

-------------------------------
KeePass CLI and dmenu interface
-------------------------------

:Author: Evan Widloski
:Copyright: GPL-3.0
:Manual group: password management

SYNOPSIS
========

**ph** [OPTIONAL ARGS] [COMMAND] [COMMAND OPTIONS] [COMMAND ARGS]

COMMANDS
========

show [-h] [--field FIELD] PATH
    Show the contents of an entry, where *PATH* is the full path to the entry.  The password field is spoilered and must be highlighted to reveal the plaintext password.  Use --field *FIELD* to print only the specified field, where *FIELD* is one of  'title', 'username', 'password', 'url', or a custom field.

type [-h] [--tabbed] [--username] [--xdotool] PROG
    Automatically type out the password as if the user had typed it on the keyboard, where *PROG* is a dmenu-like program for selecting an entry.  This is useful when you want to automatically fill a selected password field in any application.  Use the --tabbed option to type out the username then password, separated by a tab.  Use the --username option to show entry username in parenthesis during selection.  Use the --xdotool option to use xdotool instead of the Python keyboard library.  Useful for handling unicode input.  Note that this command is intended to be invoked via keyboard shortcut.
  
add [-h] [-w [LENGTH] | -a [LENGTH] | -s [LENGTH]] [--append STR] PATH
    Add a new entry/group to the database, where *PATH* is the full path to the group or entry.  Use -w, -a, or -s to generate a `correct horse battery staple`_, alphanumeric, or alphanumeric + symbolic password, respectively.  *LENGTH* defaults to 5 words for -w and 32 characters for -a and -s unless otherwise specified.  Use --append to append *STR* to the end of the generated password to meet specific password requirements.
  
.. _correct horse battery staple: http://xkcd.com/936


remove [-h] PATH
    Remove an entry/group from the database, where *PATH* is the full path to the group or entry.

edit [-h] [--field FIELD | --set FIELD VALUE | --remove FIELD] PATH
    Edit the contents of an entry, where *PATH* is the full path to the entry.  You will be prompted to edit each field value of the entry.  Use --field *FIELD* to edit only the specified field, where *FIELD* is one of  *title*, *username*, *password*, *url*, or a custom field.  Use --set *FIELD VALUE* to set the value of a field, noninteractively.  Use --remove *FIELD* to remove an existing field.

move [-h] SRC_PATH DEST_PATH
    Move an entry/group to another path, where *SRC_PATH* and *DEST_PATH* are the full paths to the source and destination items.  Providing two entry paths or two group paths will move and rename the group or entry.

list [-h] [--username] [PATH]
    List entries/groups in the database, where *PATH* is an optional path to a group or entry.  Use the --username option to show entry username in addition to title.

grep [-h] [-i] [--field FIELD] PATTERN
    List entries with titles matching a regex pattern, where *PATTERN* is an `XSLT style`_ regular expression.  Use the --field *FIELD* option to search other string fields, where *FIELD* is one of *title*, *username*, *password*, *url*, or a custom field.  Use the -i option to enable case insensitive searching.

.. _XSLT style: https://www.xml.com/pub/a/2003/06/04/tr.html

init [-h]
    Create a new database.  You will be prompted for the database password and whether or not to use a keyfile.  See --database and --keyfile to initialize in a non-default location.

dump [-h]
    Pretty print database XML to console.  Passwords will appear in plaintext.


OPTIONAL ARGS
=============

\-h, \-\-help
  Print out a help message and exit. Use in conjunction with a command for command-specific help.                                                                                                                                                   
\-\-debug
  Enable debug messages.
                                                                                                   
\-\-database PATH
  Specify the path to the KeePass database when initializing, accessing or modifying the database.  The config is ignored when this is given.

\-\-keyfile PATH
  Specify the path to the keyfile when initializing, accessing or modifying the database.  No effect if --database is not given.

\-\-cache PATH
  Specify location to cache password with gpg-agent, where *PATH* is a location on the filesystem.  No effect if --database is not given.

\-\-no-password
  Don't prompt for a password when accessing or modifying the database.  No effect if --database is not given.
                                                                                                   
\-\-gpgkey FINGERPRINT
  Specify GPG key to use when caching password, where *FINGERPRINT* is the fingerprint of the GPG key. *passhole* defaults to the first key in the keychain. Use 'gpg --list-keys --fingerprint' to get a list of keys and their fingerprints.  No effect if --database is not given.

\-v, \-\-version
  Print out version information.                                               

Files
=====

~/.config/passhole.ini
    Default location of config.  Specify multiple databases here or edit the default paths of the default database.  See the config section for supported directives.

~/.passhole.kdbx
    Default location of KeePass database. Override with --database *PATH*

~/.passhole.key
    Default location KeePass key.  Override with --keyfile *PATH* or in config.

~/.cache/passhole_cache
    Default location where gpg-agent temporarily caches the database password.  Override with --cache or in config.

Multiple Databases
==================

Multiple databases may be specified in the config.  Prefix group or entry paths with **@[Name]/**, where *[Name]* is the database name given in the config.  A path with no prefix is assumed to be the default database.

.. code:: bash

   # move an entry in the *test* database to the default database.
   $ ph mv @test/foobar_group/foobar_entry root_entry

   # list the test database
   $ ph ls @test/


Config
======

Each section in the config corresponds to a database.  The supported options are:

database: /path/to/example.kdbx
    Required. The path to the kdbx file.

keyfile: /path/to/example.key
    Path to keyfile.  If not given, assume database has no keyfile.

cache: /path/to/example.cache
    Where to cache encrypted password using GPG2.  *~/.cache/example_cache* is a good choice.  If not given, don't cache password.

no-password: True
    Assume database has no password and don't prompt for it.


Python Scripts
==============
The *open_database* function is available for import for conveniently opening your database with password caching enabled.

.. code:: python

   from passhole.passhole import open_database
   kp = open_database()


Examples
========

add a new entry with manually created password
----------------------------------------------

.. code:: bash

   $ ph add github

   Username: Evidlo
   Password: 
   Confirm: 
   URL: github.com

add an entry with a generated alphanumeric password
---------------------------------------------------

.. code:: bash

   $ ph add neopets -a
   Username: Evidlo
   URL: neopets.com

add a new group
----------------

.. code:: bash

   $ ph add social/

add an entry to `social/` with a 32 character password (alphanumeric + symbols)
--------------------------------------------------------------------------------
   
.. code:: bash

   $ ph add social/facebook -s 32
   Username: evan@evanw.org
   URL: facebook.com

add an entry to `social/` with a correct-horse-battery-staple type password
----------------------------------------------------------------------------

.. code:: bash

   $ ph add social/twitter -w
   Username: evan@evanw.org
   URL: twitter.com

list all entries
----------------

.. code:: bash

   $ ph list
   github
   neopets
   [social]
   ├── facebook
   └── twitter

display contents of entry
--------------------------

.. code:: bash

   $ ph show social/twitter
   Title: twitter
   Username: Evidlo
   Password: inns.ambien.travelling.throw.force
   URL: twitter.com

retrieve contents of specific field for use in scripts
------------------------------------------------------

.. code:: bash

   $ ph show social/twitter --field password
   inns.ambien.travelling.throw.force
