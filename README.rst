Passhole
========

``passhole`` is a CLI interface for KeePass 1.x (v3) and 2.x (v4) databases with support for dmenu inspired by `pass`_.

.. _pass: https://www.passwordstore.org

.. image:: https://i.imgur.com/lWLgbo3.gif 

- `Features`_
- `Setup`_
- `Example Usage`_
- `Example i3 Keybindings`_
- `Troubleshooting GPG Keys`_
- `Manual`_


Features
------------

- add, delete, move, rename entries and groups
- generate `correct horse battery staple`_ style passwords
- generate alphanumeric passwords
- temporarily cache database password for 10 minutes
- autofill selected forms via keyboard shortcut (using the ``type`` command)

.. _correct horse battery staple: http://xkcd.com/936

See below for examples and the `manual`_ for a complete list of commands and options.

.. _manual: MANUAL.rst

Setup
------------

.. code:: bash

   pip install passhole
   ph init

`libgpgme-dev` must also be installed.

Example Usage
--------------

.. code:: bash

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
   Username: evan@evanw.org
   URL: facebook.com

   # add an entry to `social/` with a correct-horse-battery-staple type password
   >>> ph add social/twitter -w
   Username: evan@evanw.org
   URL: twitter.com

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

   # retrieve contents of specific field for use in scripts
   >>> ph show social/twitter --field password
   inns.ambien.travelling.throw.force

Example i3 Keybindings
----------------------

.. code:: bash

   # select entry using dmenu, then send password to keyboard
   bindsym $mod+p exec "ph type dmenu"
   # select entry using dmenu, then send username + password to keyboard
   bindsym $mod+Shift+p exec "ph type dmenu --tabbed"

Troubleshooting GPG Keys
------------------------

``passhole`` uses ``gpg2`` to store your database password encrypted on disk to take advantage of the password caching features of ``gpg-agent``.  By default ``passhole`` will use the first GPG key on your keyring, but this can be overridden.  This key must have trust level 5 (ultimate) and should be created using ``gpg2``.  If you created your key with ``gpg``, you can export your keys to ``gpg2`` as shown below.

.. code:: bash

   gpg --export | gpg2 --import
   gpg --export-secret-keys | gpg2 --import

See also
--------
- `keepmenu`_
- `kpcli`_
- `keepassxc`_

.. _keepmenu: https://github.com/firecat53/keepmenu/
.. _kpcli: http://kpcli.sourceforge.net/
.. _keepassxc: https://keepassxc.org/
