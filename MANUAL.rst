SYNOPSIS
--------

**ph** [OPTIONAL ARGS] [COMMAND] [COMMAND OPTIONS] [COMMAND ARGS]

COMMANDS
--------

show [-h] [--field FIELD] PATH
    Show the contents of an entry, where ``PATH`` is the full path to the entry.  The password field is spoilered and must be highlighted to reveal the plaintext password.  Use ``--field FIELD`` to print only the specified field as plaintext, where ``FIELD`` is one of  ``title``, ``username``, ``password``, or ``url``.

type [-h] [--tabbed] [--username] [--xdotool] PROG
    Automatically type out the password as if the user had typed it on the keyboard, where ``PROG`` is a dmenu-like program for selecting an entry.  This is useful when you want to automatically fill a selected password field in any application.  Use the ``--tabbed`` option to type out the username then password, separated by a tab.  Use the ``--username`` option to show entry username in parenthesis during selection.  Use the ``--xdotool`` option to use ``xdotool`` instead of the Python keyboard library.  Useful for handling unicode input.  Note that this command is intended to be invoked via keyboard shortcut.  See the examples section.
  
add [-h] [-w [LENGTH] | -a [LENGTH] | -s [LENGTH]] PATH
    Add a new entry/group to the database, where ``PATH`` is the full path to the group or entry.  Use ``-w``, ``-a``, or ``-s`` to generate a `correct horse battery staple`_, alphanumeric, or alphanumeric + symbolic password, respectively.  ``LENGTH`` defaults to 5 words for ``-w`` and 32 characters for ``-a`` and ``-s`` unless otherwise specified.
  
.. _correct horse battery staple: http://xkcd.com/936


remove [-h] PATH
    Remove an entry/group from the database, where ``PATH`` is the full path to the group or entry.

move [-h] SRC_PATH DEST_PATH
    Move an entry/group to another path, where ``SRC_PATH`` and ``DEST_PATH`` are the full paths to the source and destination items.  Providing two entry paths or two group paths will move and rename the group or entry.

list [-h] [--username]
    List entries/groups in the database.  Use the ``--username`` option to show entry username in addition to title.

grep [-h] [-i] [--field FIELD] PATTERN
    List entries with titles matching a regex pattern, where ``PATTERN`` is an `XSLT style`_ regular expression.  Use the ``--field FIELD`` option to search other string fields, where ``FIELD`` is one of ``title``, ``username``, ``password``, ``url``, or a custom field key.  Use the ``-i`` option to enable case insensitive searching.

.. _XSLT style: https://www.xml.com/pub/a/2003/06/04/tr.html

init [-h]
    Create a new database.  You will be prompted for the database password and whether or not to use a keyfile.  See ``--database`` and ``--keyfile`` to initialize in a non-default location.

dump [-h]
    Pretty print database XML to console.  Passwords will appear in plaintext.


OPTIONAL ARGS
-------------

\-h, \-\-help
  Print out a help message and exit. Use in conjunction with a command for command-specific help.                                                                                                                                                   
\-\-debug
  Enable debug messages.
                                                                                                   
\-\-cache PATH
  Specify location to cache password with gpg-agent, where ``PATH`` is a location on the filesystem. Defaults to ``~/.cache/passhole_cache``   
  
\-\-no-cache
  Disable password caching with gpg-agent and prompt for the password every time.                                                                        
                                                                                                   
\-\-gpgkey FINGERPRINT
  Specify GPG key to use when caching password, where ``FINGERPRINT`` is the fingerprint of the GPG key. ``passhole`` defaults to the first key in the    | keychain. Use ``gpg --list-keys --fingerprint`` to get a list of keys and their fingerprints.  
  
\-\-keyfile PATH
  Specify the path to the keyfile when initializing, accessing or modifying the database. Defaults to ``~/.passhole.key``                                    

\-\-no-keyfile
  Don't use a keyfile when accessing or modifying the database.

\-\-no-password
  Don't prompt for a password when accessing or modifying the database
                                                                                                   
\-\-database PATH
  Specify the path to the KeePass database when initializing, accessing or modifying the database. Defaults to ``~/.passhole.kdbx``                     

\-v, \-\-version
  Print out version information.                                               

Files
-----
~/.passhole.kdbx
    Default location of KeePass database. Override with ``--database PATH``

~/.passhole.key
    Default location KeePass key.  Override with ``--keyfile PATH`` and disable with ``--no-keyfile``.

~/.cache/passhole_cache
    Default location where gpg agent temporarily caches the database password.  Override with ``--cache`` and disable with ``--no-cache``. 
