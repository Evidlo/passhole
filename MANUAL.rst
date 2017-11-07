SYNOPSIS
--------

**ph** [OPTIONAL ARGS] [COMMAND] [OPTIONS] [ARGS]

COMMANDS
--------

**show** [-h] PATH

    Show the contents of an entry, where ``PATH`` is the full path to the entry.  The password field is spoilered and must be highlighted to reveal the plaintext password.

**type** [-h] [--tabbed] PROG

type [-h] [--tabbed] PROG
  Automatically type out the password as if the user had typed it on the keyboard, where ``PROG`` is a dmenu-like program for selecting an entry.  This is useful when you want to automatically fill a selected password field in any application.  Use the ``--tabbed`` option to type out the username then password, separated by a tab.  Note that this command is intended to be invoked via keyboard shortcut.  See the examples section.
  
**add** [-h] [-w [length] | -a [length] | -s [length]] PATH

  Add a new entry/group to the database, where ``PATH`` is the full path to the group or entry.  Use ``-w``, ``-a``, or ``-s`` to generate a `correct horse battery staple`_, alphanumeric, or alphanumeric + symbolic password, respectively.  ``length`` defaults to 5 words for ``-w`` and 32 characters for ``-a`` and ``-s`` unless otherwise specified.
  
.. _correct horse battery staple: http://xkcd.com/936


**remove** [-h] PATH

  Remove an entry/group from the database, where ``PATH`` is the full path to the group or entry.

**list** [-h]

  List entries/groups in the database.

**init** [-h]

  Create a new database.  You will be prompted for the database password and whether or not to use a keyfile.  See ``--database`` and ``--keyfile`` to initialize in a non-default location.

.. _correct horse battery staple: http://xkcd.com/936

OPTIONAL ARGS
-------------

\-h, \-\-help

  Print out a help message and exit. Use in conjunction with a command for command-specific help.                                                                                                                                                   
\-\-debug

  Enable debug messages.
                                                                                                   
\-\-cache PATH

  Specify location to cache password with gpg-agent, where ``PATH`` is a location on the filesystem. Defaults to ``~/.cache/passhole_cache``   
  
\-\-nocache

  Disable password caching with gpg-agent and prompt for the password every time.                                                                        
                                                                                                   
\-\-gpgkey FINGERPRINT

  Specify GPG key to use when caching password, where ``FINGERPRINT`` is the fingerprint of the GPG key. ``passhole`` defaults to the first key in the    | keychain. Use ``gpg --list-keys --fingerprint`` to get a list of keys and their fingerprints.  
  
\-\-keyfile PATH

  Specify the path to the keyfile when initializing, accessing or modifying the database. Defaults to ``~/.passhole.key``                                    
\-\-nokeyfile

  Don't use a keyfile when accessing or modifying the database.
                                                                                                   
\-\-database PATH

  Specify the path to the KeePass database when initializing, accessing or modifying the database. Defaults to ``~/.passhole.kdbx``                     

\-v, \-\-version

  Print out version information.                                               
                                                                                                   

Examples
--------

.. code:: bash

   # initialize the database
   >>> ph init
   Creating database at /home/evan/.passhole.kdbx
   Enter your desired database password
   Password:
   Confirm:

   # add a new entry with manually created password
   >>> ph add github
   Username: Evidlo
   Password: 
   Confirm: 
   URL: github.com

   # add an entry with a generated alphanumeric password
   >>> ph add neopets -a
   Username: Evidlo
   URL: neopets.com

   # add a new group
   >>> ph add social/
   
   # add an entry to `social/` with a 32 character password (alphanumeric + symbols)
   >>> ph add social/facebook -s 32

   # add an entry to `social/` with a correct-horse-battery-staple type password
   >>> ph add social/twitter -w

   # list all entries
   >>> ph list
   github
   neopets
   [social]
   ├── facebook
   └── twitter

   # display contents of entry
   >>> ph show social/twitter
   Title: twitter
   Username: Evidlo
   Password: inns.ambien.travelling.throw.force
   URL: twitter.com

Example i3wm config

.. code:: bash

   # select entry using dmenu, then send password to keyboard
   bindsym $mod+p exec ph type dmenu
   # select entry using dmenu, then send username + password to keyboard
   bindsym $mod+Shift+p ph type --tabbed dmenu
​
