Passhole
========

.. image:: https://img.shields.io/matrix/pykeepass:matrix.org.svg
   :target: https://matrix.to/#/#pykeepass:matrix.org


``passhole`` is a commandline password manager for KeePass inspired by `pass`_.

.. _pass: https://www.passwordstore.org

.. image:: https://i.imgur.com/lWLgbo3.gif 

- `Manual`_
- `Features`_
- `Setup`_
- `Example Usage`_
- `Example i3wm Keybindings`_
- `Testing and Development`_


Features
------------

- fill user/pass field in any application via keyboard shortcut
- add, delete, move, edit, rename entries and groups
- generate alphanumeric, symbolic, or `correct horse battery staple`_ style passwords
- temporarily cache database password (by default for 10 minutes)
- multiple databases
- supports KeePass v3 and v4 databases
- supports TOTP

.. _correct horse battery staple: http://xkcd.com/936

See below for examples and the `manual`_ (or ``man passhole``) for a complete list of commands and options.

.. _manual: https://github.com/evidlo/passhole/tree/master/MANUAL.rst

Setup
------------

.. code:: bash

   pip install passhole
   ph init
   
   # optionally install zenity for graphical password prompt
   sudo apt install zenity


Example Usage
--------------

.. code:: bash

   # add a new entry with manually created password
   $ ph add github
   Username: Evidlo
   Password: 
   Confirm: 
   URL: github.com

   # add an entry with a generated alphanumeric password
   $ ph add neopets -a
   Username: Evidlo
   URL: neopets.com

   # add a new group
   $ ph add social/
   
   # add an entry to `social/` with a 32 character password (alphanumeric + symbols)
   $ ph add social/facebook -s 32
   Username: evan@evanw.org
   URL: facebook.com

   # add an entry to `social/` with a correct-horse-battery-staple type password
   $ ph add social/twitter -w
   Username: evan@evanw.org
   URL: twitter.com

   # list all entries
   $ ph list
   github
   neopets
   [social]
   ├── facebook
   └── twitter

   # display contents of entry
   $ ph show social/twitter
   Title: twitter
   Username: Evidlo
   Password: inns.ambien.travelling.throw.force
   URL: twitter.com

   # retrieve contents of specific field for use in scripts
   $ ph show social/twitter --field password
   inns.ambien.travelling.throw.force

Example i3wm Keybindings
------------------------

.. code:: bash

   # select entry using dmenu, then send password to keyboard
   bindsym $mod+p exec "ph type --prog dmenu"

   # select entry using dmenu, then send username + password to keyboard
   bindsym $mod+Shift+p exec "ph type --tabbed --prog dmenu"

Testing and Development
-----------------------

Running tests

.. code:: bash

   # from repo root dir:
   python test/tests.py

Isolated install in Docker

.. code:: bash

   # debian
   make docker_debian

Building manpage and packaging

.. code:: bash

   make man
   make dist

See also
--------
- `keepmenu`_
- `kpcli`_
- `keepassxc`_
- `kdbxpasswordpwned`_

.. _keepmenu: https://github.com/firecat53/keepmenu/
.. _kpcli: http://kpcli.sourceforge.net/
.. _keepassxc: https://keepassxc.org/
.. _kdbxpasswordpwned: https://github.com/fopina/kdbxpasswordpwned

Build Dependencies
---------------------------

Alpine

    apk add gcc libffi-dev py3-lxml py3-pip python3-dev libc-dev
