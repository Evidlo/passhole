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

show [-h] [--field FIELD] [--totp] PATH
    Show the contents of an entry, where *PATH* is the full path to the entry.  The password field is spoilered and must be highlighted to reveal the plaintext password.  Use --field *FIELD* to print only the specified field, where *FIELD* is one of  'title', 'username', 'password', 'url', or a custom field.  The --totp option will parse any OTP URIs and print the code.

type [-h] [--prog PROG] [--tabbed] [--totp] [--xdotool] [--username] [--duration TIME] [--delay TIME] [name]
    Automatically type out the password as if the user had typed it on the keyboard, where *PROG* is a dmenu-like program for selecting an entry.  *PROG* defaults to 'dmenu'.  This is useful when you want to automatically fill a selected password field in any application.  *name* is the name of the database to type from.  If not given, type from all databases.  Use the --tabbed option to type out the username then password, separated by a tab. Use the --totp option to generate and type otp using 'otp' attribute. Use the --username option to show entry username in parenthesis during selection.  Use the --xdotool option to use xdotool instead of the Python keyboard library.  Useful for handling unicode input. Use --duration to specify the time in seconds for which a key should be pressed when typing (defaults to 0.012) and --delay to set the time between to separate key strokes.  Note that this command is intended to be invoked via keyboard shortcut.

add [-h] [-w [LENGTH] | -a [LENGTH] | -s [LENGTH]] [--append STR] [--fields FIELD1,...] PATH
    Add a new entry/group to the database, where *PATH* is the full path to the entry or group.  Use -w, -a, or -s to generate a `correct horse battery staple`_, alphanumeric, or alphanumeric + symbolic password, respectively.  *LENGTH* defaults to 5 words for -w and 32 characters for -a and -s unless otherwise specified.  Use --append to append *STR* to the end of the generated password to meet specific password requirements.  Use --fields to specify a comma separated list of custom fields to prompt for during entry creation.
  
.. _correct horse battery staple: http://xkcd.com/936


remove [-h] PATH
    Remove an entry/group from the database, where *PATH* is the full path to the entry or group.

edit [-h] [--field FIELD | --set FIELD VALUE | --remove FIELD] PATH
    Edit the contents of an entry or group, where *PATH* is the full path to the entry or group.  You will be prompted to edit each field value.  Use --field *FIELD* to edit only the specified field, where *FIELD* is one of  *title*, *username*, *password*, *url*, or a custom field when editing entries.  This option has no effect for groups.  Use --set *FIELD VALUE* to set the value of a field, noninteractively for entries.  Only *name* is supported for groups.  Use --remove *FIELD* to remove an existing custom entry field.  This option has no effect for groups.

move [-h] SRC_PATH DEST_PATH
    Move an entry/group to another path, where *SRC_PATH* and *DEST_PATH* are the full paths to the source and destination items.  Providing two entry paths or two group paths will move and rename the entry or group.

list [-h] [--username] [PATH]
    List entries/groups in the database, where *PATH* is an optional path to a entry or group.  Use the --username option to show entry username in addition to title.

grep [-h] [-i] [--field FIELD] PATTERN
    List entries with titles matching a regex pattern, where *PATTERN* is an `XSLT style`_ regular expression.  Use the --field *FIELD* option to search other string fields, where *FIELD* is one of *title*, *username*, *password*, *url*, or a custom field.  Use the -i option to enable case insensitive searching.

.. _XSLT style: https://www.xml.com/pub/a/2003/06/04/tr.html

kill [-h]
    Kill the background server.

restart [-h]
    Restart the background server.

init [-h] [--name NAME] [--database DATABASE] [--password PASSWORD] [--keyfile KEYFILE]
    Create a new database.  You will be prompted for the database password and whether or not to use a keyfile.  See --database and --keyfile to initialize in a non-default location.

eval [-h] [--json] CODE
    Evaluate CODE as Python code.  Variable ``kp`` is in scope
for accessing the database.  ``ag`` is also available as shorthand for ``operator.attrgetter``.  If --json is provided, CODE will be evaluated and should be an expression which returns a JSON-serializable result.  Otherwise, CODE is executed and the printing is left up to the user (the ``json`` library is in scope for serialization.)

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

\-\-password PASSWORD
  Supply password directly (possibly insecure), or read it from stdin when supplied '-'

\-\-no-password
  Don't prompt for a password when accessing or modifying the database.  No effect if --database is not given.                                                              

\-\-no-cache
  Don't read from or write to cache while opening this database.

\-\-cache-timeout
  Timeout to read from or write to cache while opening this database. No effect if --no-cache=True

\-\-config PATH
  Specify path to config.

\-v, \-\-version
  Print out version information.                                               

Files
=====

~/.config/passhole.ini
    Default location of config.  Specify multiple databases here or edit database options.  See the config section for supported directives.

~/.local/passhole.kdbx
    Default location of KeePass database. Override with --database *PATH*

~/.local/passhole.key
    Default location KeePass key.  Override with --keyfile *PATH* or in config.

Config
======

Located at *~/.config/passhole.ini* by default.  Can be overriden with the --config option.  Each section in the config corresponds to a database.  The supported options are:

database: /path/to/example.kdbx
    Required. The path to the kdbx file.

keyfile: /path/to/example.key
    Optional.  Path to keyfile.  If not given, assume database has no keyfile.

no-password: True
    Optional.  Assume database has no password and don't prompt for it.  If not given, the password will be loaded from cache or the user prompted.

no-cache: True
    Optional.  Don't read from or write to cache when opening this database.

cache-timeout: 300
  Seconds to keep databases open in cache. Cache timeout is the same for all open databases and should be set in the first section in the config.  The timeout timer resets with each passhole invocation.  No effect if no-cache=True

default: True
    Optional.  Set this database as default.  When using multiple databases, entry or group paths with no **@[Name]** database prefix are assumed to refer to this database.


Multiple Databases
==================

All commands support multiple databases.  Prefix entry or group paths with **@[Name]/**, where *[Name]* is the database name given in the config.  A path with no prefix is assumed to be the default database.

.. code:: bash

   # move an entry in the *test* database to the default database.
   $ ph mv @test/foobar_group/foobar_entry root_entry

   # list the test database
   $ ph ls @test/

More databases may be added using the init command or manually specified in the config:

.. code::

    [test]
    # Use this database as the default
    # default: True
    # Path to database (required)
    database: /path/to/test.kdbx
    # Path to keyfile.  if absent, assume no keyfile
    keyfile: /path/to/test.key
    # Does the database have a password?
    # no-password: True
    # Path to password cache.  If absent, don't cache password.
    # Must be unique for each database
    cache: ~/.cache/test_cache


Python Scripts
==============
The *open_database* function is available for use in scripts to conveniently open the default database.  When ``all=True``, it returns a list of tuples of the form ('[NAME]', [PyKeePass object]), where NAME is specified in the config.

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

custom evaluated expressions
----------------------------

Get title of all entries whose URLs start with 't'

.. code:: bash

   $ ph eval -j 'map(attrgetter("title"), filter(lambda e: (e.url or "").startswith("t"), kp.entries))'
   ["twitter"]

Same example as above, but with multiline code in a Bash Heredoc

.. code:: bash

   ph eval - <<EOF
   titles = []
   for e in kp.entries:
       if (e.url or "").startswith("t"):
           titles.append(e.title)
   print(json.dumps(titles))
   EOF

Same example again, but using underlying PyKeePass API

.. code:: bash

   ph eval -j 'map(ag("title"), kp.find_entries(url="^t.*", regex=True))'